"""Shared dashboard entry point. Streamlit shows every file in frontend/pages/ as a menu item.
Do not put component logic here; put it in your own page file."""
import streamlit as st

st.set_page_config(page_title="J26-CS-328 Industrial IoT SOC", layout="wide")
st.title("Explainable AI-Driven IDS and SOC Automation for Industrial IoT")
st.write("Use the menu on the left: 1 Detection, 2 Explainability, 3 SOC Prioritisation, 4 Forensics.")
