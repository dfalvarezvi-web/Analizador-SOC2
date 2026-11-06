import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile
import os
import hashlib

# Configuración inicial de la página
st.set_page_config(
    page_title="SOC Advisory - Auditoría ISO 27001 & Ciberseguridad",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Centro de Operaciones de Seguridad (SOC) | Consultoría & SGSI ISO 27001")
st.markdown("Plataforma avanzada de análisis forense, correlación de eventos y trazabilidad normativa bajo estándares internacionales.")

# ----------------------------------------------------
# 1. CARGA Y NORMALIZACIÓN DE DATOS
# ----------------------------------------------------
st.sidebar.header("📁 1. Ingesta de Logs (SIEM)")
uploaded_file = st.sidebar.file_uploader("Subir archivo de registros (.xlsx)", type=["xlsx"])

if uploaded_file is not None:
    try:
        file_bytes = uploaded_file.getvalue()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        file_name_original = uploaded_file.name

        df = pd.read_excel(uploaded_file)
        df.columns = df.columns.astype(str).str.strip()
        
        if 'Timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        
        st.sidebar.success("¡Logs cargados y normalizados con éxito!")
        
        with st.expander("🔍 Vista previa de registros crudos (Raw Logs) y Cadena de Custodia"):
            st.text(f"Nombre del archivo: {file_name_original}")
            st.text(f"Hash SHA-256 (Íntegro): {file_hash}")
            st.dataframe(df, use_container_width=True)
            
        # ----------------------------------------------------
        # 2. MOTOR DE CORRELACIÓN Y ALINEACIÓN ISO 27001
        # ----------------------------------------------------
        def clasificar_incidente(row):
            sev = str(row.get('Severity', '')).lower()
            desc = str(row.get('Event_Description', '')).lower()
            cmd = str(row.get('Process_CommandLine', '')).lower()
            res = str(row.get('Result', '')).lower()
            
            if 'high' in sev or 'critical' in sev or any(k in desc for k in ['rce', 'malware', 'ransomware', 'exploit']) or any(c in cmd for c in ['powershell', 'cmd.exe /c', 'invoke-webrequest', 'base64']):
                return 'Crítico', 'Ejecución de código malicioso o explotación. Incumplimiento potencial de Controles ISO 27001: A.8.7 (Protección contra Malware) y A.8.16 (Monitoreo).'
            elif 'medium' in sev or 'warning' in sev or 'fail' in res or 'denied' in res:
                return 'Alto', 'Fallo de autenticación reiterado o acceso denegado. Impacto en Control ISO 27001: A.9.4.2 / A.5.17 (Control de Acceso).'
            elif 'informational' in sev and ('logon' in desc or 'process' in desc):
                return 'Medio', 'Evento operativo relevante. Trazabilidad requerida por Control ISO 27001: A.8.15 (Registro de Eventos).'
            else:
                return 'Bajo', 'Actividad rutinaria sin impacto crítico en la infraestructura ni desviaciones del SGSI.'

        df_analisis = df.copy()
        resultados = df_analisis.apply(clasificar_incidente, axis=1)
        df_analisis['Criticidad_Consultoria'] = [r[0] for r in resultados]
        df_analisis['Justificacion_Tecnica'] = [r[1] for r in resultados]

        # ----------------------------------------------------
        # 3. FILTROS INTERACTIVOS DE CONSULTORÍA
        # ----------------------------------------------------
        st.sidebar.header("⚙️ 3. Filtros de Auditoría")
        severidades_sel = st.sidebar.multiselect(
            "Filtrar por Criticidad:",
            options=['Crítico', 'Alto', 'Medio', 'Bajo'],
            default=['Crítico', 'Alto', 'Medio', 'Bajo']
        )
        
        hosts_disponibles = df_analisis['Hostname'].unique().tolist() if 'Hostname' in df_analisis.columns else []
        hosts_sel = st.sidebar.multiselect("Filtrar por Hostname:", options=hosts_disponibles, default=hosts_disponibles)
        
        if not hosts_sel or not severidades_sel:
            st.warning("⚠️ Por favor, selecciona al menos una criticidad y un host en la barra lateral para visualizar los datos.")
            st.stop()

        df_filtrado = df_analisis[
            (df_analisis['Criticidad_Consultoria'].isin(severidades_sel)) &
            (df_analisis['Hostname'].isin(hosts_sel))
        ]

        # ----------------------------------------------------
        # 4. DASHBOARD EJECUTIVO Y ALERTAS DINÁMICAS
        # ----------------------------------------------------
        st.header("📊 4. Dashboard Ejecutivo de Incidentes y Frecuencia")
        
        total_logs = len(df_filtrado)
        criticos_cnt = len(df_filtrado[df_filtrado['Criticidad_Consultoria'] == 'Crítico'])
        altos_cnt = len(df_filtrado[df_filtrado['Criticidad_Consultoria'] == 'Alto'])
        hosts_comprometidos = df_filtrado[df_filtrado['Criticidad_Consultoria'].isin(['Crítico', 'Alto'])]['Hostname'].nunique()
        
        if criticos_cnt > 0:
            st.error(f"🚨 **ALTA AMENAZA DETECTADA:** Se han identificado {criticos_cnt} eventos críticos que afectan la conformidad del SGSI. Se requiere contención inmediata.")
        elif altos_cnt > 0:
            st.warning(f"⚠️ **ADVERTENCIA DE SEGURIDAD:** Se registran {altos_cnt} anomalías de nivel alto.")
        else:
            st.success("✅ **ESTADO ESTABLE:** No se detectan anomalías críticas en el filtrado actual.")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Registros Filtrados", total_logs)
        col2.metric("Incidentes Críticos", criticos_cnt, delta_color="inverse")
        col3.metric("Incidentes Altos", altos_cnt)
        col4.metric("Hosts Afectados", hosts_comprometidos)
        
        col_g1, col_g2 = st.columns(2)
        with col_g1:
            fig_pie = px.pie(
                df_filtrado, 
                names='Criticidad_Consultoria', 
                title='Distribución Porcentual de Riesgo',
                color='Criticidad_Consultoria',
                color_discrete_map={'Crítico':'#ff4b4b', 'Alto':'#ffa15a', 'Medio':'#ffcc00', 'Bajo':'#00cc96'}
            )
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with col_g2:
            if 'Timestamp' in df_filtrado.columns and not df_filtrado.empty:
                df_freq = df_filtrado.dropna(subset=['Timestamp']).copy()
                if not df_freq.empty:
                    df_freq['Time_Group'] = df_freq['Timestamp'].dt.floor('h')
                    df_freq_grouped = df_freq.groupby(['Time_Group', 'Criticidad_Consultoria']).size().reset_index(name='Frecuencia')
                    fig_time = px.line(
                        df_freq_grouped, 
                        x='Time_Group', 
                        y='Frecuencia', 
                        color='Criticidad_Consultoria',
                        title='Línea de Tiempo y Frecuencia de Incidentes',
                        color_discrete_map={'Crítico':'#ff4b4b', 'Alto':'#ffa15a', 'Medio':'#ffcc00', 'Bajo':'#00cc96'}
                    )
                    st.plotly_chart(fig_time, use_container_width=True)

        # ----------------------------------------------------
        # 5. MATRIZ DETALLADA Y PLAN DE CONSULTORÍA
        # ----------------------------------------------------
        st.header("📋 5. Detalle de Registros y Hallazgos Forenses")
        columnas_vista = [col for col in ['Log_ID', 'Timestamp', 'Hostname', 'User', 'Source_IP', 'Event_Description', 'Severity', 'Criticidad_Consultoria', 'Justificacion_Tecnica'] if col in df_filtrado.columns]
        st.dataframe(df_filtrado[columnas_vista], use_container_width=True)

        # ----------------------------------------------------
        # 6. GENERACIÓN DE INFORME PROFESIONAL EN PDF CON ALINEACIÓN ISO 27001
        # ----------------------------------------------------
        st.header("📥 6. Exportación de Entregable Ejecutivo para Cliente")
        
        def generar_pdf_consultoria(df_resumen, nombre_log, hash_log):
            pdf = FPDF()
            pdf.add_page()
            
            # Encabezado
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 7, "INFORME TÉCNICO SOC & CUMPLIMIENTO ISO/IEC 27001", 0, 1, "C")
            pdf.set_font("Arial", "I", 7.5)
            pdf.cell(0, 4, "Análisis Forense, Gestión de Incidentes y Evaluación de Controles Normativos", 0, 1, "C")
            pdf.ln(2)
            
            # Metadatos del artefacto
            pdf.set_font("Arial", "B", 7.5)
            pdf.cell(0, 4.5, f"Artefacto Analizado: {nombre_log}", 0, 1)
            pdf.cell(0, 4.5, f"Hash SHA-256 (Integridad): {hash_log[:32]}...", 0, 1)
            pdf.cell(0, 4.5, f"Fecha de Emisión: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')} | Total Registros: {len(df_resumen)}", 0, 1)
            pdf.cell(0, 4.5, f"Críticos: {criticos_cnt} | Altos: {altos_cnt} | Marco de Referencia: ISO/IEC 27001:2022", 0, 1)
            pdf.ln(2)
            
            # 1. Resumen Ejecutivo
            pdf.set_font("Arial", "B", 8.5)
            pdf.cell(0, 4.5, "1. Resumen Ejecutivo y Evaluación de Riesgo (ISO 27001 Cláusula 6)", 0, 1)
            pdf.set_font("Arial", "", 6.5)
            resumen_texto = (
                f"La auditoría sobre el archivo '{nombre_log}' identifica {criticos_cnt} desviaciones críticas y "
                f"{altos_cnt} anomalías operativas. Estos eventos impactan la efectividad del Sistema de Gestión de Seguridad de la Información (SGSI), "
                f"requiriendo la aplicación inmediata de los controles de tratamiento de riesgos estipulados por la norma."
            )
            pdf.multi_cell(0, 3, resumen_texto.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(1.5)
            
            # 2. Plan de Acción, Plazos y Controles ISO 27001
            pdf.set_font("Arial", "B", 8.5)
            pdf.cell(0, 4.5, "2. Plan de Acción, Tiempos y Controles ISO/IEC 27001 Asociados", 0, 1)
            
            pdf.set_font("Arial", "B", 7)
            pdf.cell(0, 3.5, "[INMEDIATO / 0 - 24 Horas] Contención (Control ISO A.5.24 - Gestión de Incidentes):", 0, 1)
            pdf.set_font("Arial", "", 6.5)
            pdf.multi_cell(0, 3, "- Aislamiento preventivo de los hosts comprometidos para evitar propagación.\n- Revocación de sesiones y rotación obligatoria de credenciales afectadas.".encode('latin-1', 'replace').decode('latin-1'))
            
            pdf.set_font("Arial", "B", 7)
            pdf.cell(0, 3.5, "[CORTO PLAZO / 1 - 7 Días] Mitigación (Controles ISO A.8.7 y A.8.16):", 0, 1)
            pdf.set_font("Arial", "", 6.5)
            pdf.multi_cell(0, 3, "- Auditoría profunda de comandos ejecutados vía consola (Process_CommandLine).\n- Reforzamiento del monitoreo y revisión de logs perimetrales.".encode('latin-1', 'replace').decode('latin-1'))

            pdf.set_font("Arial", "B", 7)
            pdf.cell(0, 3.5, "[LARGO PLAZO / 30 - 90 Días] Gobernanza (Controles ISO A.5.17 y A.9.12):", 0, 1)
            pdf.set_font("Arial", "", 6.5)
            pdf.multi_cell(0, 3, "- Despliegue de políticas estrictas de control de privilegios (Least Privilege).\n- Automatización de playbooks de respuesta en el SIEM y capacitación en ciberseguridad.".encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(1.5)
            
            # 3. Principales Hallazgos Forenses
            pdf.set_font("Arial", "B", 8.5)
            pdf.cell(0, 4.5, "3. Principales Hallazgos Forenses (Top Registros)", 0, 1)
            pdf.set_font("Arial", "", 6)
            
            for _, row in df_resumen.head(15).iterrows():
                log_id = str(row.get('Log_ID', 'N/A'))
                host = str(row.get('Hostname', 'N/A'))
                crit = str(row.get('Criticidad_Consultoria', 'N/A'))
                just = str(row.get('Justificacion_Tecnica', 'N/A'))
                linea = f"[{log_id}] Host: {host} | Nivel: {crit} - {just}"
                pdf.cell(0, 3, linea.encode('latin-1', 'replace').decode('latin-1'), 0, 1)
                
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
            pdf.output(tmp_file.name)
            return tmp_file.name

        if "pdf_generated_path" not in st.session_state:
            st.session_state.pdf_generated_path = None

        if st.button("📄 Generar Informe de Consultoría PDF con Alineación ISO 27001"):
            with st.spinner("Compilando reporte forense avanzado y generando PDF..."):
                st.session_state.pdf_generated_path = generar_pdf_consultoria(df_filtrado, file_name_original, file_hash)
            st.success("¡Informe generado con éxito!")

        if st.session_state.pdf_generated_path and os.path.exists(st.session_state.pdf_generated_path):
            with open(st.session_state.pdf_generated_path, "rb") as f:
                st.download_button(
                    label="⬇️ Descargar PDF Profesional para Cliente (ISO 27001)",
                    data=f,
                    file_name="Informe_ISO27001_SOC.pdf",
                    mime="application/pdf"
                )
                
    except Exception as e:
        st.error(f"Error al procesar el archivo Excel. Detalles: {e}")
else:
    st.info("👈 Por favor, carga tu archivo de logs (`.xlsx`) en la barra lateral para iniciar la consultoría de seguridad.")
