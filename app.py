"""Punto de entrada para Vercel (Flask). Solo expone el panel de Dani.

Variables de entorno (Vercel → Settings → Environment Variables):
  APE_PANEL_DSN        conexión del rol ape_panel (cadena del pooler de Supabase)
  APE_APPROVAL_SECRET  clave de aprobaciones: cualquier cadena aleatoria de 32+ caracteres
  APE_SETUP_TOKEN      código de un solo uso para la primera configuración
  (opcionales)  APE_GITHUB_TOKEN, APE_GITHUB_REPO, APE_GITHUB_WORKFLOW  →  botón «Ejecutar ciclo ahora»
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from ape.panel.app import PanelConfig, create_app  # noqa: E402

app = create_app(PanelConfig.from_env())
