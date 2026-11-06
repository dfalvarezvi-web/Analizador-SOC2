import streamlit as st
import pandas as pd
import plotly.express as px
import matplotlib.pyplot as plt
from fpdf import FPDF
import tempfile
import os
import hashlib

# ----------------------------------------------------
# CONFIGURACIÓN INICIAL Y ESTILOS VISUALES (MORADOS Y AMARILLO)
# ----------------------------------------------------
st.set_page_config(
    page_title="SOC ADVISORY DAV - Auditoría y Ciberseguridad",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
    <style>
    .main {
        background-color: #0f172a;
        color: #f8fafc;
    }
    .stMetric {
        background-color: #1e1b4b;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #7c3aed;
        box-shadow: 0 4px 6px -1px rgba(124, 58, 237, 0.2);
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ SOC ADVISORY DAV | Centro de Operaciones de Seguridad")
st.markdown("### Plataforma Avanzada de Análisis Forense, Correlación SIEM y Gobernanza SGSI")

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
        
        with st.expander("🔍 Ver Detalle del Artefacto y Cadena de Custodia (Hash SHA-256)"):
            st.text(f"• Nombre del archivo analizado: {file_name_original}")
            st.text(f"• Hash SHA-256 (Garantía de Integridad): {file_hash}")
            st.dataframe(df.head(10), use_container_width=True)
            
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
        # 4. EXPLICACIÓN DETALLADA DEL ANÁLISIS REALIZADO
        # ----------------------------------------------------
        st.markdown("---")
        st.subheader("📑 Memoria Técnica y Detalle del Análisis Realizado")
        st.markdown(
            "El presente análisis evalúa la telemetría y los registros de eventos de seguridad (SIEM) ingestados mediante "
            "un motor de correlación heurística basado en matrices de riesgo corporativas y marcos de referencia internacionales "
            "como **MITRE ATT&CK** y **ISO/IEC 27001:2022**."
        )
        st.markdown("---")

        # ----------------------------------------------------
        # 5. DASHBOARD EJECUTIVO Y ALERTAS DINÁMICAS (Paleta Morados y Amarillo)
        # ----------------------------------------------------
        st.header("📊 Dashboard Ejecutivo de Incidentes y Frecuencia")
        
        total_logs = len(df_filtrado)
        criticos_cnt = len(df_filtrado[df_filtrado['Criticidad_Consultoria'] == 'Crítico'])
        altos_cnt = len(df_filtrado[df_filtrado['Criticidad_Consultoria'] == 'Alto'])
        hosts_comprometidos = df_filtrado[df_filtrado['Criticidad_Consultoria'].isin(['Crítico', 'Alto'])]['Hostname'].nunique()
        
        if criticos_cnt > 0:
            st.error(f"🚨 **ALTA AMENAZA DETECTADA:** Se han identificado {criticos_cnt} eventos críticos. Se requiere contención inmediata.")
        elif altos_cnt > 0:
            st.warning(f"⚠️ **ADVERTENCIA DE SEGURIDAD:** Se registran {altos_cnt} anomalías de nivel alto.")
        else:
            st.success("✅ **ESTADO ESTABLE:** No se detectan anomalías críticas en el filtrado actual.")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Registros Filtrados", total_logs)
        col2.metric("Incidentes Críticos", criticos_cnt, delta_color="inverse")
        col3.metric("Incidentes Altos", altos_cnt)
        col4.metric("Hosts Afectados", hosts_comprometidos)
        
        # Paleta de colores: Morados y Amarillo
        color_palette = {
            'Crítico': '#eab308',  # Amarillo brillante
            'Alto': '#facc15',     # Amarillo claro
            'Medio': '#a855f7',    # Morado claro
            'Bajo': '#6b21a8'      # Morado oscuro
        }

        col_g1, col_g2 = st.columns(2)
        with col_g1:
            fig_pie = px.pie(
                df_filtrado, 
                names='Criticidad_Consultoria', 
                title='Distribución Porcentual de Riesgo',
                color='Criticidad_Consultoria',
                color_discrete_map=color_palette
            )
            fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
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
                        color_discrete_map=color_palette
                    )
                    fig_time.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
                    st.plotly_chart(fig_time, use_container_width=True)

        # ----------------------------------------------------
        # 6. MATRIZ DETALLADA Y FILTRO DE JUSTIFICACIONES TÉCNICAS
        # ----------------------------------------------------
        st.header("📋 Detalle de Registros y Hallazgos Forenses")
        
        # NUEVO: Filtro interactivo para justificaciones técnicas
        busqueda_justificacion = st.text_input("🔍 Filtrar Hallazgos por Texto en Justificación Técnica:", "")
        df_vista_tabla = df_filtrado.copy()
        if busqueda_justificacion:
            df_vista_tabla = df_vista_tabla[df_vista_tabla['Justificacion_Tecnica'].str.contains(busqueda_justificacion, case=False, na=False)]

        columnas_vista = [col for col in ['Log_ID', 'Timestamp', 'Hostname', 'User', 'Source_IP', 'Event_Description', 'Severity', 'Criticidad_Consultoria', 'Justificacion_Tecnica'] if col in df_vista_tabla.columns]
        st.dataframe(df_vista_tabla[columnas_vista], use_container_width=True)

        # ----------------------------------------------------
        # 7. GENERACIÓN DE INFORME PDF CON MATPLOTLIB (GRÁFICOS GARANTIZADOS)
        # ----------------------------------------------------
        st.header("📥 Exportación de Entregable Ejecutivo para Cliente")
        
        class PDFReport(FPDF):
            def __init__(self):
                super().__init__(orientation='P', unit='mm', format='A4')
                self.set_auto_page_break(auto=True, margin=15)
                
            def header(self):
                # Banda superior en tono morado oscuro institucional
                self.set_fill_color(30, 27, 75)
                self.rect(0, 0, 210, 18, 'F')
                self.set_font('Arial', 'B', 9)
                self.set_text_color(250, 204, 21) # Amarillo claro
                self.set_xy(10, 5)
                self.cell(100, 8, 'SOC ADVISORY DAV | INFORME TÉCNICO EJECUTIVO', 0, 0, 'L')
                self.set_xy(110, 5)
                self.cell(90, 8, 'ISO/IEC 27001:2022 COMPLIANCE', 0, 0, 'R')
                self.ln(22)
                
            def footer(self):
                self.set_y(-12)
                self.set_font('Arial', 'I', 7.5)
                self.set_text_color(128, 128, 128)
                self.cell(0, 8, f'Página {self.page_no()} | SOC ADVISORY DAV - Documento Confidencial', 0, 0, 'C')

        def generar_pdf_consultoria(df_resumen, nombre_log, hash_log):
            pdf = PDFReport()
            pdf.add_page()
            
            pdf.set_font("Arial", "B", 13)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 6, "INFORME DE AUDITORÍA FORENSE Y CUMPLIMIENTO SGSI", 0, 1, "L")
            pdf.set_font("Arial", "", 8.5)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4, f"Fecha de Emisión: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')} | Marco: ISO/IEC 27001:2022", 0, 1, "L")
            pdf.ln(3)
            
            # Caja Metadatos
            pdf.set_fill_color(245, 243, 255)
            pdf.rect(10, pdf.get_y(), 190, 18, 'F')
            pdf.set_xy(12, pdf.get_y() + 2)
            pdf.set_font("Arial", "B", 8)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(90, 4, f"Artefacto Analizado: {nombre_log}", 0, 0)
            pdf.cell(95, 4, f"Total Registros Analizados: {len(df_resumen)}", 0, 1)
            pdf.set_x(12)
            pdf.cell(185, 4, f"Hash SHA-256 (Integridad Forense): {hash_log}", 0, 1)
            pdf.ln(6)
            
            # Resumen Ejecutivo
            pdf.set_font("Arial", "B", 9.5)
            pdf.cell(0, 5, "1. Resumen Ejecutivo y Detalle del Análisis Realizado", 0, 1)
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(50, 50, 50)
            resumen_texto = (
                f"Mediante SOC ADVISORY DAV, se completó la auditoría forense sobre el archivo '{nombre_log}'. "
                f"Se detectaron {criticos_cnt} eventos críticos y {altos_cnt} anomalías operativas. "
                f"El análisis coteja la telemetría con controles normativos para mitigar desvíos del SGSI y riesgos de explotación."
            )
            pdf.multi_cell(0, 4, resumen_texto.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(4)
            
            # GENERACIÓN DE GRÁFICOS CON MATPLOTLIB (INCRUSTACIÓN DIRECTA EN PDF)
            pie_path = None
            try:
                pdf.set_font("Arial", "B", 9.5)
                pdf.set_text_color(30, 27, 75)
                pdf.cell(0, 5, "2. Análisis Estadístico y Distribución de Riesgos", 0, 1)
                pdf.ln(2)
                
                fig, ax = plt.subplots(figsize=(5, 3))
                counts = df_resumen['Criticidad_Consultoria'].value_counts()
                chart_colors = ['#eab308', '#a855f7', '#7c3aed', '#6b21a8'][:len(counts)]
                ax.pie(counts, labels=counts.index, autopct='%1.1f%%', colors=chart_colors, textprops={'fontsize': 8})
                ax.set_title('Distribución de Riesgos (SOC ADVISORY DAV)', fontsize=9, color='#1e1b4b', fontweight='bold')
                
                pie_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
                plt.savefig(pie_path, bbox_inches='tight', dpi=150)
                plt.close(fig)
                
                # Insertar gráfico centrado en el PDF A4
                pdf.image(pie_path, x=55, y=pdf.get_y(), w=100)
                pdf.ln(60)
            except Exception as chart_err:
                pdf.set_font("Error generando gráficos: " + str(chart_err), "", 7)
                pdf.ln(4)

            if pie_path and os.path.exists(pie_path):
                try: os.unlink(pie_path)
                except: pass

            # Plan de Acción e ISO 27001
            pdf.set_font("Arial", "B", 9.5)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "3. Plan de Acción, Tiempos y Controles ISO/IEC 27001", 0, 1)
            pdf.ln(1)
            
            pdf.set_font("Arial", "B", 8)
            pdf.set_fill_color(230, 225, 250)
            pdf.cell(45, 5, "Plazo / Horizonte", 1, 0, "C", fill=True)
            pdf.cell(75, 5, "Acciones de Mitigación / Medida", 1, 0, "C", fill=True)
            pdf.cell(70, 5, "Control ISO 27001:2022", 1, 1, "C", fill=True)
            
            pdf.set_font("Arial", "", 7.5)
            pdf.cell(45, 6, "Inmediato (0 - 24 h)", 1, 0)
            pdf.cell(75, 6, "Aislamiento de hosts y revocación de credenciales.", 1, 0)
            pdf.cell(70, 6, "Control A.5.24 (Gestión de Incidentes)", 1, 1)
            
            pdf.cell(45, 6, "Corto Plazo (1 - 7 días)", 1, 0)
            pdf.cell(75, 6, "Auditoría de comandos y hardening perimetral.", 1, 0)
            pdf.cell(70, 6, "Controles A.8.7 y A.8.16 (Monitoreo)", 1, 1)
            
            pdf.cell(45, 6, "Largo Plazo (30 - 90 días)", 1, 0)
            pdf.cell(75, 6, "Mínimo privilegio y automatización SIEM.", 1, 0)
            pdf.cell(70, 6, "Controles A.5.17 y A.9.12 (Accesos)", 1, 1)
            pdf.ln(4)
            
            # Hallazgos Forenses
            pdf.set_font("Arial", "B", 9.5)
            pdf.cell(0, 5, "4. Principales Hallazgos Forenses (Top Registros)", 0, 1)
            pdf.set_font("Arial", "", 7)
            
            for _, row in df_resumen.head(15).iterrows():
                log_id = str(row.get('Log_ID', 'N/A'))
                host = str(row.get('Hostname', 'N/A'))
                crit = str(row.get('Criticidad_Consultoria', 'N/A'))
                just = str(row.get('Justificacion_Tecnica', 'N/A'))
                linea = f"[{log_id}] Host: {host} | Nivel: {crit} - {just}"
                pdf.cell(0, 4, linea.encode('latin-1', 'replace').decode('latin-1'), 0, 1)
                
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
            pdf.output(tmp_file.name)
            return tmp_file.name

        if "pdf_generated_path" not in st.session_state:
            st.session_state.pdf_generated_path = None

        if st.button("📄 Generar Informe Ejecutivo PDF Profesional (SOC ADVISORY DAV)"):
            with st.spinner("Compilando reporte A4 corporativo, renderizando gráficos y generando PDF..."):
                st.session_state.pdf_generated_path = generar_pdf_consultoria(df_filtrado, file_name_original, file_hash)
            st.success("¡Informe generado con éxito bajo estándares A4 y gráficos incluidos!")

        if st.session_state.pdf_generated_path and os.path.exists(st.session_state.pdf_generated_path):
            with open(st.session_state.pdf_generated_path, "rb") as f:
                st.download_button(
                    label="⬇️ Descargar PDF Profesional para Cliente (SOC ADVISORY DAV)",
                    data=f,
                    file_name="Informe_ISO27001_SOC_ADVISORY_DAV.pdf",
                    mime="application/pdf"
                )
                
    except Exception as e:
        st.error(f"Error al procesar el archivo Excel. Detalles: {e}")
else:
    st.info("👈 Por favor, carga tu archivo de logs (`.xlsx`) en la barra lateral para iniciar la consultoría de seguridad con SOC ADVISORY DAV.")
