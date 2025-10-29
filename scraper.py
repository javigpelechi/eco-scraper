import os
import re
import time
import json
import sqlite3
import unicodedata
import urllib.parse
import argparse
from datetime import datetime, timezone, timedelta
from typing import List, Tuple, Optional, Dict

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import yaml  # PyYAML

# zoneinfo (3.9+). En Windows puede requerir paquete 'tzdata'.
try:
    from zoneinfo import ZoneInfo
    ZONE_MADRID = ZoneInfo("Europe/Madrid")
except Exception:
    ZONE_MADRID = None  # fallback: usaremos UTC si no está

# -----------------------------
# Configuración
# -----------------------------

CONFIG_PATH = "config.yml"
DB_PATH = "seen.db"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

def load_yaml(path: str) -> dict:
    """Carga robusta del config.yml usando PyYAML y pone valores por defecto."""
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    cfg.setdefault("topics", [])
    cfg.setdefault("search", {})
    cfg.setdefault("notify", {})
    cfg.setdefault("filter", {})

    # Búsqueda
    cfg["search"].setdefault("base", "https://www.eleconomista.es")
    cfg["search"].setdefault("template", "https://www.eleconomista.es/buscador/resultados.php?fondo={query}")
    cfg["search"].setdefault("timeout_seconds", 15)
    cfg["search"].setdefault("pause_between_topics_ms", 800)

    # Notificación
    cfg["notify"].setdefault("batch_per_topic", True)
    cfg["notify"].setdefault("max_links_per_message", 10)

    # Filtro de coincidencias
    cfg["filter"].setdefault("title_must_match", True)
    cfg["filter"].setdefault("also_match_description", False)

    return cfg

# -----------------------------
# Base de datos (evitar duplicados)
# -----------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seen (
            topic TEXT NOT NULL,
            url   TEXT NOT NULL,
            title TEXT,
            first_seen_utc TEXT NOT NULL,
            PRIMARY KEY (topic, url)
        )
        """
    )
    conn.commit()
    return conn

def already_seen(conn, topic: str, url: str) -> bool:
    cur = conn.execute("SELECT 1 FROM seen WHERE topic=? AND url=? LIMIT 1", (topic, url))
    return cur.fetchone() is not None

def mark_seen(conn, topic: str, url: str, title: str):
    conn.execute(
        "INSERT OR IGNORE INTO seen(topic, url, title, first_seen_utc) VALUES (?,?,?,?)",
        (topic, url, title, datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    conn.commit()

# -----------------------------
# Normalización y coincidencias
# -----------------------------

def _strip_accents(s: str) -> str:
    if not s:
        return ""
    return "".join(ch for ch in unicodedata.normalize("NFD", s) if unicodedata.category(ch) != "Mn")

def _norm(s: str) -> str:
    return _strip_accents(s).lower().strip()

def title_matches_topic(title: str, topic: str) -> bool:
    """
    True si el titular contiene la palabra/frase del topic
    como bloque (no subcadena parcial), insensible a acentos y mayúsculas.
    """
    nt = _norm(title)
    nq = _norm(topic)
    if not nt or not nq:
        return False
    pattern = re.compile(rf"(?<!\w){re.escape(nq)}(?!\w)")
    return bool(pattern.search(nt))

# -----------------------------
# Utilidades de scraping
# -----------------------------

def normalize_url(u: str) -> str:
    """Quita parámetros y 'amp.' del host para evitar duplicados."""
    parsed = urllib.parse.urlparse(u)
    netloc = parsed.netloc.replace("amp.", "")
    return urllib.parse.urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))

def is_article_url(u: str, base: str) -> bool:
    """
    Acepta solo artículos .html del dominio de El Economista.
    Excluye listados/secciones y branded content.
    """
    try:
        parsed = urllib.parse.urlparse(u)
        host = base.replace("https://", "").replace("http://", "")
        if host not in parsed.netloc:
            return False
        path = parsed.path.lower()
        if "/branded-content/" in path:
            return False
        return path.endswith(".html")
    except Exception:
        return False

def fetch_search_results(session: requests.Session, search_template: str, topic: str, timeout: int) -> Tuple[str, BeautifulSoup]:
    url = search_template.format(query=urllib.parse.quote_plus(topic))
    resp = session.get(url, timeout=timeout)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "lxml")
    return url, soup

def extract_links_from_search(soup: BeautifulSoup, base: str) -> List[Tuple[str, str]]:
    """
    Extrae (title, url) desde la página de resultados del buscador.
    Filtra a solo artículos válidos (.html) y deduplica por URL.
    """
    candidates: List[Tuple[str, str]] = []
    for a in soup.select("a"):
        href = (a.get("href") or "").strip()
        text = a.get_text(strip=True)
        if not href or not text:
            continue
        abs_href = urllib.parse.urljoin(base, href)
        if is_article_url(abs_href, base):
            candidates.append((text, normalize_url(abs_href)))

    # dedup por URL
    seen = set()
    unique: List[Tuple[str, str]] = []
    for title, url in candidates:
        if url not in seen:
            seen.add(url)
            unique.append((title, url))
    return unique

# -----------------------------
# Metadatos del artículo (título/fecha/description + dt)
# -----------------------------

def _parse_iso_to_dt(date_iso: str) -> Optional[datetime]:
    """Parsea varias formas ISO → datetime con tz (UTC si no hay tz). Devuelve None si no se puede."""
    if not date_iso:
        return None
    try:
        dt = None
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z"):
            try:
                dt = datetime.strptime(date_iso, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            date_iso_trim = re.split(r"[^0-9TZ:+-]", date_iso)[0]
            dt = datetime.fromisoformat(date_iso_trim)  # puede lanzar ValueError
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def _format_dt_ddmm(dt: Optional[datetime]) -> str:
    if not dt:
        return "??/??"
    try:
        if ZONE_MADRID:
            dt = dt.astimezone(ZONE_MADRID)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%d/%m")
    except Exception:
        return "??/??"

def get_article_meta(session: requests.Session, url: str) -> Tuple[str, str, str, Optional[datetime]]:
    """
    Devuelve (title, date_str, description, date_dt) para el artículo.
    - title: og:title o <title>
    - date_str: dd/MM
    - description: meta[name="description"]
    - date_dt: datetime con tz si se pudo parsear (UTC-based)
    """
    try:
        r = session.get(url, timeout=15)
        r.raise_for_status()
        art = BeautifulSoup(r.text, "lxml")

        # Título
        title = ""
        ogt = art.select_one('meta[property="og:title"]')
        if ogt and ogt.get("content"):
            title = ogt["content"].strip()
        if not title:
            t = art.select_one("title")
            if t and t.get_text(strip=True):
                title = t.get_text(strip=True)

        # Fecha (probar varios metadatos)
        date_iso = ""
        for sel in [
            'meta[property="article:published_time"]',
            'meta[name="article:published_time"]',
            'meta[property="og:article:published_time"]',
            'meta[name="date"]',
            'meta[property="og:updated_time"]',
        ]:
            m = art.select_one(sel)
            if m and m.get("content"):
                date_iso = m["content"].strip()
                break

        # <time datetime="...">
        if not date_iso:
            ttag = art.select_one("time[datetime]")
            if ttag and ttag.get("datetime"):
                date_iso = ttag["datetime"].strip()

        date_dt = _parse_iso_to_dt(date_iso)
        date_str = _format_dt_ddmm(date_dt)

        # Descripción
        desc = ""
        md = art.select_one('meta[name="description"]')
        if md and md.get("content"):
            desc = md["content"].strip()

        return (title or "", date_str, desc or "", date_dt)
    except Exception:
        return ("", "??/??", "", None)

# -----------------------------
# Envío a Teams
# -----------------------------

def post_to_teams(webhook_url: str, text: str):
    payload = {"text": text}
    r = requests.post(
        webhook_url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=15,
    )
    r.raise_for_status()

def format_batch_message(topic: str, items: List[Tuple[str, str, str]], max_links: int) -> str:
    """
    items: lista de (title, url, date_str)
    """
    count = min(len(items), max_links)
    lines = [f"🗞️ **Nuevas noticias sobre _{topic}_** ({count}):"]
    for title, url, d in items[:max_links]:
        ttl = title if title and len(title) <= 180 else (title[:177] + "…") if title else url
        lines.append(f"• {d} — {ttl}\n  {url}")
    if len(items) > max_links:
        lines.append(f"… y {len(items) - max_links} más.")
    return "\n".join(lines)

def format_single_message(topic: str, title: str, url: str, d: str) -> str:
    ttl = title if title and len(title) <= 180 else (title[:177] + "…") if title else url
    return f"🗞️ {d} — {ttl}\n{url}"

# -----------------------------
# Main
# -----------------------------

def run(dry_run: bool, seed_days: int):
    load_dotenv()
    cfg = load_yaml(CONFIG_PATH)

    webhook = (os.getenv("TEAMS_WEBHOOK_URL") or "").strip()
    if not webhook and seed_days <= 0:
        raise RuntimeError("Falta TEAMS_WEBHOOK_URL en el archivo .env")

    topics = cfg["topics"]
    base = cfg["search"]["base"]
    search_template = cfg["search"]["template"]
    timeout = int(cfg["search"]["timeout_seconds"])
    pause_ms = int(cfg["search"]["pause_between_topics_ms"])
    batch_per_topic = bool(cfg["notify"]["batch_per_topic"])
    max_links = int(cfg["notify"]["max_links_per_message"])

    title_must_match = bool(cfg["filter"]["title_must_match"])
    also_match_description = bool(cfg["filter"]["also_match_description"])

    if not topics:
        print("No hay temas en config.yml → añade al menos uno en 'topics'.")
        return

    conn = init_db()
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "es-ES,es;q=0.9"})

    total_new = 0
    cutoff_dt = None
    if seed_days and seed_days > 0:
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=seed_days)
        print(f"[SEED] Solo marcar como vistos artículos desde los últimos {seed_days} días (>= {cutoff_dt.isoformat(timespec='seconds')})")

    # Para el mensaje de resumen/debug
    per_topic_status: Dict[str, str] = {}

    # Para publicar después del resumen
    per_topic_found: Dict[str, List[Tuple[str, str, str]]] = {t: [] for t in topics}

    for topic in topics:
        try:
            _, soup = fetch_search_results(session, search_template, topic, timeout)
            items = extract_links_from_search(soup, base)

            # Filtra novedades contra la base
            raw_new = [(t, u) for t, u in items if not already_seen(conn, topic, u)]

            # Enriquecer con título/fecha/desc/dt reales desde el artículo
            enriched_full: List[Tuple[str, str, str, str, Optional[datetime]]] = []
            for t, u in raw_new:
                real_title, date_str, desc, date_dt = get_article_meta(session, u)
                enriched_full.append((real_title or t, u, date_str, desc, date_dt))

            # Filtro de coincidencia por titular (y opcional descripción)
            filtered_full: List[Tuple[str, str, str, str, Optional[datetime]]] = []
            for t, u, d_str, desc, d_dt in enriched_full:
                ok = title_matches_topic(t, topic) if title_must_match else True
                if not ok and also_match_description and desc:
                    ok = title_matches_topic(desc, topic)
                if ok:
                    filtered_full.append((t, u, d_str, desc, d_dt))

            if seed_days and seed_days > 0:
                # MODO SEED: NO enviar a Teams. Solo marcar vistos si la fecha >= cutoff (si se pudo determinar).
                seeded = 0
                for t, u, d_str, desc, d_dt in filtered_full:
                    if d_dt and d_dt >= cutoff_dt:
                        mark_seen(conn, topic, u, t)
                        seeded += 1
                per_topic_status[topic] = f"{topic}: marcados {seeded} recientes."
                total_new += seeded
            else:
                # Modo normal (con o sin dry_run)
                filtered = [(t, u, d_str) for (t, u, d_str, _, _) in filtered_full]
                if filtered:
                    per_topic_status[topic] = f"{topic}: {len(filtered)} nuevas."
                    total_new += len(filtered)
                    per_topic_found[topic] = filtered
                else:
                    per_topic_status[topic] = f"{topic}: sin novedades."

                # Marca como vistos ya (se publiquen ahora o luego)
                for t, u, _ in filtered:
                    mark_seen(conn, topic, u, t)

        except requests.HTTPError as e:
            per_topic_status[topic] = f"[ERROR HTTP] {topic}: {e}"
        except Exception as e:
            per_topic_status[topic] = f"[ERROR] {topic}: {e}"

        time.sleep(pause_ms / 1000.0)

    if seed_days and seed_days > 0:
        print(f"Sembrado completado. Artículos marcados: {total_new}")
        return

    # --------- ENVÍO DE RESUMEN ("debug") Y LUEGO NOTICIAS ----------
    # Timestamp local del sistema (respeta DST)
    now_local = datetime.now().astimezone()
    header = f"Scrap del día {now_local.strftime('%d/%m/%Y')} a las {now_local.strftime('%H:%M')}"

    lines = [header, ""]
    lines.extend(per_topic_status[t] for t in topics)
    lines.append(f"Finalizado. Total de nuevas noticias: {total_new}")
    summary_text = "\n".join(lines)

    if not dry_run:
        try:
            post_to_teams(webhook, summary_text)
        except Exception as e:
            print(f"[WARN] Falló el post del resumen a Teams: {e}")

        # Ahora, por cada tema, mandar sus artículos (si hay)
        for topic in topics:
            found = per_topic_found.get(topic) or []
            if not found:
                continue
            if batch_per_topic:
                try:
                    msg = format_batch_message(topic, found, max_links)
                    post_to_teams(webhook, msg)
                except Exception as e:
                    print(f"[WARN] Falló el post de artículos ({topic}): {e}")
            else:
                for t, u, d in found[:max_links]:
                    try:
                        post_to_teams(webhook, format_single_message(topic, t, u, d))
                    except Exception as e:
                        print(f"[WARN] Falló el post de un artículo ({topic}): {e}")
    else:
        print(summary_text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scraper El Economista → Teams")
    parser.add_argument("--dry-run", action="store_true", help="No envía a Teams; solo muestra y marca vistos")
    parser.add_argument("--seed-days", type=int, default=0, help="Sembrar la base marcando como vistos artículos de los últimos N días (no envía a Teams). Ej: --seed-days 5")
    args = parser.parse_args()

    run(dry_run=args.dry_run, seed_days=args.seed_days)
