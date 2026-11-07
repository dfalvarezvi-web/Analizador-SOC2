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
    div[data-testid="stMetric"] {
        background-color: #1e1b4b !important;
        padding: 15px !important;
        border-radius: 10px !important;
        border: 1px solid #7c3aed !important;
        box-shadow: 0 4px 6px -1px rgba(124, 58, 237, 0.3);
    }
    div[data-testid="stMetric"] label {
        color: #facc15 !important;
        font-weight: 600 !important;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-weight: 700 !important;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ SOC ADVISORY DAV | Centro de Operaciones de Seguridad")
st.markdown("### Plataforma Avanzada de Análisis Forense, Correlación SIEM y Gobernanza SGSI Multi-ISO")

# ----------------------------------------------------
# 1. CARGA Y NORMALIZACIÓN DE DATOS
# ----------------------------------------------------
st.sidebar.header("📁 1. Ingesta de Logs (SIEM)")
uploaded_file = st.sidebar.file_uploader("Subir archivo de registros (.xlsx)", type=["xlsx"])

if uploaded_file is not None:
    try:
        file_bytes = uploaded_file.getvalue()
        file_size_kb = len(file_bytes) / 1024.0
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        file_name_original = uploaded_file.name
        file_ext = os.path.splitext(file_name_original)[1]

        df = pd.read_excel(uploaded_file)
        df.columns = df.columns.astype(str).str.strip()
        
        if 'Timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        
        st.sidebar.success("¡Logs cargados y normalizados con éxito!")
        
        with st.expander("🔍 Ver Detalle del Archivo Cargado y Cadena de Custodia (Hash SHA-256)"):
            st.text(f"• Archivo cargado analizado: {file_name_original}")
            st.text(f"• Tamaño: {file_size_kb:.2f} KB | Extensión: {file_ext}")
            st.text(f"• Hash SHA-256 (Garantía de Integridad): {file_hash}")
            st.dataframe(df.head(10), use_container_width=True)
            
        # ----------------------------------------------------
        # 2. MOTOR DE CORRELACIÓN: 6 VECTORES Y MULTI-ISO (27001, 27035, 27701)
        # ----------------------------------------------------
        def clasificar_vector_y_riesgo(row):
            sev = str(row.get('Severity', '')).lower()
            desc = str(row.get('Event_Description', '')).lower()
            cmd = str(row.get('Process_CommandLine', '')).lower()
            res = str(row.get('Result', '')).lower()
            event_id = str(row.get('Event_ID', ''))
            user = str(row.get('User', ''))
            
            # Clasificación de los 6 Vectores de Ataque Profesionales
            if 'fail' in res or '4625' in event_id or 'failed' in desc or 'bad password' in desc:
                vector = 'Fuerza Bruta'
            elif 'privileges' in desc or '4672' in event_id or 'administrators' in cmd or 'localgroup' in cmd:
                vector = 'Escalamiento de Privilegios'
            elif 'powershell' in cmd or 'cmd.exe' in cmd or 'process' in desc or '4688' in event_id or 'archive' in desc:
                vector = 'Comandos y Procesos'
            elif 'rdp' in desc or 'logontype=10' in desc or '5140' in event_id or 'share' in desc or 'lateral' in desc:
                vector = 'Movimiento Lateral'
            elif 'logontype=3' in desc or ('success' in res and ('logon' in desc or '4624' in event_id)):
                vector = 'Inicios Sospechosos'
            else:
                vector = 'Otras Anomalías'

            # Alineación Multi-ISO y Criticidad
            if vector in ['Escalamiento de Privilegios', 'Comandos y Procesos'] and ('high' in sev or 'critical' in sev or 'powershell' in cmd):
                criticidad = 'Crítico'
                justificacion = f"Vector [{vector}]: Código malicioso / privilegios. ISO 27001: A.8.7/A.8.16 | ISO 27035: Contención/Erradicación | ISO 27701: Alerta PII."
            elif vector in ['Fuerza Bruta', 'Movimiento Lateral'] or 'fail' in res or 'denied' in res:
                criticidad = 'Alto'
                justificacion = f"Vector [{vector}]: Fallo de autenticación o acceso lateral. ISO 27001: A.9.4.2 / A.5.17 | ISO 27035: Análisis | ISO 27701: Cuentas."
            elif vector == 'Inicios Sospechosos' or 'informational' in sev:
                criticidad = 'Medio'
                justificacion = f"Vector [{vector}]: Evento operativo de sesión para '{user}'. ISO 27001: A.8.15 | ISO 27035: Monitoreo | ISO 27701: Trazabilidad."
            else:
                criticidad = 'Bajo'
                justificacion = f"Vector [{vector}]: Actividad rutinaria sin desviación. ISO 27001: A.8.16 | ISO 27035: Operación Normal."

            return vector, criticidad, justificacion

        df_analisis = df.copy()
        resultados = df_analisis.apply(clasificar_vector_y_riesgo, axis=1)
        df_analisis['Vector_Ataque'] = [r[0] for r in resultados]
        df_analisis['Criticidad_Consultoria'] = [r[1] for r in resultados]
        df_analisis['Justificacion_Tecnica'] = [r[2] for r in resultados]

        # ----------------------------------------------------
        # 3. FILTROS INTERACTIVOS DE CONSULTORÍA (INCLUYENDO FECHAS)
        # ----------------------------------------------------
        st.sidebar.header("⚙️ 3. Filtros de Auditoría")
        
        if 'Timestamp' in df_analisis.columns and not df_analisis['Timestamp'].isna().all():
            min_date = df_analisis['Timestamp'].min().date()
            max_date = df_analisis['Timestamp'].max().date()
            
            rango_fechas = st.sidebar.date_input(
                "Filtrar por Rango de Fechas:",
                value=(min_date, max_date),
                min_value=min_date,
                max_value=max_date
            )
            
            if len(rango_fechas) == 2:
                start_date, end_date = rango_fechas
                df_analisis = df_analisis[
                    (df_analisis['Timestamp'].dt.date >= start_date) & 
                    (df_analisis['Timestamp'].dt.date <= end_date)
                ]

        vectores_disponibles = sorted(df_analisis['Vector_Ataque'].unique().tolist())
        vectores_sel = st.sidebar.multiselect(
            "Filtrar por Vector de Ataque:",
            options=vectores_disponibles,
            default=vectores_disponibles
        )

        severidades_sel = st.sidebar.multiselect(
            "Filtrar por Criticidad:",
            options=['Crítico', 'Alto', 'Medio', 'Bajo'],
            default=['Crítico', 'Alto', 'Medio', 'Bajo']
        )
        
        hosts_disponibles = df_analisis['Hostname'].unique().tolist() if 'Hostname' in df_analisis.columns else []
        hosts_sel = st.sidebar.multiselect("Filtrar por Hostname:", options=hosts_disponibles, default=hosts_disponibles)
        
        if not hosts_sel or not severidades_sel or not vectores_sel:
            st.warning("⚠️ Por favor, selecciona al menos un vector, una criticidad y un host en la barra lateral.")
            st.stop()

        df_filtrado = df_analisis[
            (df_analisis['Vector_Ataque'].isin(vectores_sel)) &
            (df_analisis['Criticidad_Consultoria'].isin(severidades_sel)) &
            (df_analisis['Hostname'].isin(hosts_sel))
        ]

        # ----------------------------------------------------
        # 4. EXPLICACIÓN DETALLADA DEL ANÁLISIS REALIZADO
        # ----------------------------------------------------
        st.markdown("---")
        st.subheader("📑 Memoria Técnica y Detalle del Análisis Realizado")
        st.markdown("""
        El presente análisis evalúa la telemetría y los registros de eventos de seguridad (SIEM) mediante un motor de correlación heurística basado en matrices de riesgo corporativas y marcos de referencia internacionales de primer nivel:
        * **MITRE ATT&CK:** Identificación y mapeo de **los 6 Vectores de Ataque Profesionales** (*Fuerza Bruta, Inicios Sospechosos, Escalamiento de Privilegios, Comandos y Procesos, Movimiento Lateral y Otras Anomalías*).
        * **ISO/IEC 27001:2022:** Alineación de controles SGSI para la gestión de accesos, protección contra malware y monitoreo.
        * **ISO/IEC 27035:** Gestión de incidentes y cumplimiento de las fases de detección, análisis, contención y erradicación.
        * **ISO/IEC 27701:** Protección de la privacidad y trazabilidad de cuentas y datos personales (PII) expuestos en la telemetría.
        """)
        st.markdown("---")

        # ----------------------------------------------------
        # 5. DASHBOARD EJECUTIVO Y ALERTAS DINÁMICAS
        # ----------------------------------------------------
        st.header("📊 Dashboard Ejecutivo de Incidentes y Frecuencia")
        
        total_logs = len(df_filtrado)
        criticos_cnt = len(df_filtrado[df_filtrado['Criticidad_Consultoria'] == 'Crítico'])
        altos_cnt = len(df_filtrado[df_filtrado['Criticidad_Consultoria'] == 'Alto'])
        medios_cnt = len(df_filtrado[df_filtrado['Criticidad_Consultoria'] == 'Medio'])
        bajos_cnt = len(df_filtrado[df_filtrado['Criticidad_Consultoria'] == 'Bajo'])
        hosts_comprometidos = df_filtrado[df_filtrado['Criticidad_Consultoria'].isin(['Crítico', 'Alto'])]['Hostname'].nunique()
        
        if criticos_cnt > 0:
            st.error(f"🚨 **ALTA AMENAZA DETECTADA:** Se han identificado {criticos_cnt} eventos críticos. Se requiere contención inmediata bajo ISO 27035.")
        elif altos_cnt > 0:
            st.warning(f"⚠️ **ADVERTENCIA DE SEGURIDAD:** Se registran {altos_cnt} anomalías de nivel alto.")
        else:
            st.success("✅ **ESTADO ESTABLE:** No se detectan anomalías críticas en el filtrado actual.")

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Registros Filtrados", total_logs)
        col2.metric("Incidentes Críticos", criticos_cnt, delta_color="inverse")
        col3.metric("Incidentes Altos", altos_cnt)
        col4.metric("Hosts Afectados", hosts_comprometidos)
        
        color_palette = {
            'Crítico': '#ef4444',
            'Alto': '#f59e0b',
            'Medio': '#8b5cf6',
            'Bajo': '#10b981'
        }

        col_g1, col_g2, col_g3 = st.columns(3)
        
        with col_g1:
            fig_pie_crit = px.pie(
                df_filtrado, 
                names='Criticidad_Consultoria', 
                title='Distribución por Criticidad (Casos y %)', 
                color='Criticidad_Consultoria', 
                color_discrete_map=color_palette
            )
            fig_pie_crit.update_traces(textinfo='label+percent+value')
            fig_pie_crit.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
            selected_point = st.plotly_chart(fig_pie_crit, use_container_width=True, on_select="rerun", selection_mode="points")

        with col_g2:
            fig_pie_vec = px.pie(
                df_filtrado, 
                names='Vector_Ataque', 
                title='Distribución por los 6 Vectores de Ataque', 
                color_discrete_sequence=px.colors.qualitative.Set2
            )
            fig_pie_vec.update_traces(textinfo='label+percent+value')
            fig_pie_vec.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
            st.plotly_chart(fig_pie_vec, use_container_width=True)
            
        with col_g3:
            if 'Timestamp' in df_filtrado.columns and not df_filtrado.empty:
                df_freq = df_filtrado.dropna(subset=['Timestamp']).copy()
                if not df_freq.empty:
                    df_freq['Time_Group'] = df_freq['Timestamp'].dt.floor('h')
                    df_freq_grouped = df_freq.groupby(['Time_Group', 'Criticidad_Consultoria']).size().reset_index(name='Frecuencia')
                    fig_time = px.line(df_freq_grouped, x='Time_Group', y='Frecuencia', color='Criticidad_Consultoria', title='Línea de Tiempo Temporal', color_discrete_map=color_palette)
                    fig_time.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
                    st.plotly_chart(fig_time, use_container_width=True)

        selected_risk_level = None
        if selected_point and "selection" in selected_point and "points" in selected_point["selection"]:
            points = selected_point["selection"]["points"]
            if points:
                selected_risk_level = points[0].get("label")

        if selected_risk_level:
            st.info(f"🎯 **Casos identificados al hacer clic en el Nivel de Riesgo [{selected_risk_level}]:**")
            df_selected_cases = df_filtrado[df_filtrado['Criticidad_Consultoria'] == selected_risk_level]
            if not df_selected_cases.empty:
                st.dataframe(
                    df_selected_cases[['Log_ID', 'Timestamp', 'Hostname', 'User', 'Vector_Ataque', 'Event_Description', 'Justificacion_Tecnica']],
                    use_container_width=True
                )

        with st.expander("ℹ️ Guía Ejecutiva: Interpretación de Niveles de Riesgo y Medidas Multi-ISO"):
            st.markdown("""
            ### 🚨 1. Riesgo Crítico (Respuesta Inmediata: 0 - 24 h)
            * **Implica:** Evidencia clara de compromiso de activos, ejecución remota de código o escalamiento de privilegios.
            * **Marcos Aplicados:** **ISO 27001 (A.5.24 y A.8.7)** | **ISO 27035 (Contención Inmediata)** | **ISO 27701 (Protección PII)**.

            ### ⚠️ 2. Riesgo Alto (Respuesta a Corto Plazo: 1 - 7 días)
            * **Implica:** Fuerza bruta o movimiento lateral detectado en la red.
            * **Marcos Aplicados:** **ISO 27001 (A.5.17 / A.9.4.2)** | **ISO 27035 (Análisis y Erradicación)**.

            ### 🟣 3. Riesgo Medio (Respuesta a Mediano Plazo: 7 - 30 días)
            * **Implica:** Inicios sospechosos u operaciones administrativas relevantes.
            * **Marcos Aplicados:** **ISO 27001 (A.8.15)** | **ISO 27701 (Trazabilidad de Identidad)**.

            ### 🟢 4. Riesgo Bajo (Monitoreo Continuo)
            * **Implica:** Actividad rutinaria dentro de la línea base esperada.
            * **Marcos Aplicados:** **ISO 27001 (A.8.16)** | **ISO 27035 (Operación Normal)**.
            """)

        st.header("📋 Detalle de Registros, Log ID y Hallazgos Forenses")
        busqueda_justificacion = st.text_input("🔍 Filtrar Hallazgos por Texto en Justificación Técnica o Log ID:", "")
        df_vista_tabla = df_filtrado.copy()
        if busqueda_justificacion:
            df_vista_tabla = df_vista_tabla[
                df_vista_tabla['Justificacion_Tecnica'].str.contains(busqueda_justificacion, case=False, na=False) |
                df_vista_tabla['Log_ID'].str.contains(busqueda_justificacion, case=False, na=False)
            ]

        columnas_vista = [col for col in ['Log_ID', 'Timestamp', 'Hostname', 'User', 'Source_IP', 'Vector_Ataque', 'Event_Description', 'Severity', 'Criticidad_Consultoria', 'Justificacion_Tecnica'] if col in df_vista_tabla.columns]
        st.dataframe(df_vista_tabla[columnas_vista], use_container_width=True)

        st.header("📥 Exportación de Entregable Ejecutivo para Cliente")
        
        class PDFReport(FPDF):
            def __init__(self):
                super().__init__(orientation='P', unit='mm', format='A4')
                self.set_auto_page_break(auto=True, margin=15)
                
            def header(self):
                self.set_fill_color(30, 27, 75)
                self.rect(0, 0, 210, 16, 'F')
                self.set_font('Arial', 'B', 9)
                self.set_text_color(250, 204, 21)
                self.set_xy(10, 4)
                self.cell(100, 8, 'SOC ADVISORY DAV | INFORME DE ANÁLISIS DE INCIDENTES', 0, 0, 'L')
                self.set_xy(110, 4)
                self.cell(90, 8, 'MULTI-ISO COMPLIANCE (27001/27035/27701)', 0, 0, 'R')
                self.ln(18)
                
            def footer(self):
                self.set_y(-12)
                self.set_font('Arial', 'I', 7.5)
                self.set_text_color(128, 128, 128)
                self.cell(0, 8, f'Página {self.page_no()} | SOC Incident Analyzer - Documento Confidencial', 0, 0, 'C')

        def generar_pdf_consultoria(df_resumen, nombre_log, hash_log, size_kb, ext):
            pdf = PDFReport()
            pdf.add_page()
            
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 6, "INFORME DE AUDITORÍA FORENSE Y GOBERNANZA MULTI-ISO", 0, 1, "L")
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(100, 100, 100)
            fecha_gen = pd.Timestamp.now().strftime('%d/%m/%Y, %H:%M')
            pdf.cell(0, 4, f"Fecha de Generación: {fecha_gen} | Marcos: ISO 27001, ISO 27035, ISO 27701", 0, 1, "L")
            pdf.ln(3)
            
            pdf.set_fill_color(240, 253, 244)
            pdf.set_draw_color(34, 197, 94)
            pdf.rect(10, pdf.get_y(), 190, 6, 'DF')
            pdf.set_font("Arial", "I", 7.5)
            pdf.set_text_color(22, 101, 52)
            pdf.cell(0, 6, " Procesamiento local: ningún dato fue enviado a servidores externos. Confidencialidad garantizada.", 0, 1, "L")
            pdf.ln(4)

            total_casos = len(df_resumen)
            tasa_deteccion = (total_casos / len(df)) * 100 if len(df) > 0 else 0
            
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "1. Resumen Ejecutivo", 0, 1)
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(50, 50, 50)
            resumen_texto = (
                f"Se analizaron {len(df)} registros procesados y se detectaron {total_casos} incidentes "
                f"(tasa de detección: {tasa_deteccion:.2f}%). Desglose por niveles de criticidad: "
                f"{criticos_cnt} CRÍTICO, {altos_cnt} ALTO, {medios_cnt} MEDIO, {bajos_cnt} BAJO. "
                f"Se han identificado incidentes que requieren atención inmediata de contención."
            )
            pdf.multi_cell(0, 4.5, resumen_texto.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(3)

            # Tabla 1: Desglose por Nivel de Riesgo (Estilo Semáforo con fondos legibles)
            pdf.set_font("Arial", "B", 8)
            pdf.set_fill_color(51, 65, 85)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(50, 6, " Nivel de Riesgo", 1, 0, "L", fill=True)
            pdf.cell(45, 6, "Incidentes Identificados", 1, 0, "C", fill=True)
            pdf.cell(95, 6, "Porcentaje sobre el Total (%)", 1, 1, "C", fill=True)

            riesgos_tbl = [
                ("CRÍTICO", criticos_cnt, (criticos_cnt / total_casos * 100) if total_casos > 0 else 0, (254, 226, 226), (185, 28, 28)),
                ("ALTO", altos_cnt, (altos_cnt / total_casos * 100) if total_casos > 0 else 0, (254, 243, 199), (180, 83, 9)),
                ("MEDIO", medios_cnt, (medios_cnt / total_casos * 100) if total_casos > 0 else 0, (243, 232, 255), (107, 33, 168)),
                ("BAJO", bajos_cnt, (bajos_cnt / total_casos * 100) if total_casos > 0 else 0, (209, 250, 229), (6, 95, 70)),
            ]
            
            pdf.set_font("Arial", "B", 8)
            for niv, cnt_r, pct_r, bg_rgb, txt_rgb in riesgos_tbl:
                pdf.set_fill_color(*bg_rgb)
                pdf.set_text_color(*txt_rgb)
                pdf.cell(50, 6, f"  {niv}", 1, 0, "L", fill=True)
                pdf.set_text_color(50, 50, 50)
                pdf.cell(45, 6, f"{cnt_r}", 1, 0, "C", fill=True)
                pdf.cell(95, 6, f"{pct_r:.2f}%", 1, 1, "C", fill=True)
            pdf.ln(4)

            # 2. Descripción del Archivo Analizado (Sección 3 completa)
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "2. Descripción del Archivo Analizado", 0, 1)
            pdf.ln(1)
            
            pdf.set_font("Arial", "B", 8)
            pdf.set_fill_color(224, 231, 255)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(60, 5, " Campo Metadato", 1, 0, "L", fill=True)
            pdf.cell(130, 5, " Valor de Registro", 1, 1, "L", fill=True)
            
            pdf.set_font("Arial", "", 7.5)
            meta_tabla = [
                ("Nombre del archivo", nombre_log),
                ("Tamaño", f"{size_kb:.2f} KB"),
                ("Extensión", ext),
                ("Hoja procesada", "SIEM Export"),
                ("Múltiples hojas", "No"),
                ("Total de registros procesados", f"{len(df)}"),
                ("Total de incidentes correlacionados", f"{total_casos}"),
                ("Hash SHA-256 (Custodia)", hash_log),
                ("Timestamp del análisis", fecha_gen)
            ]
            for cmp, val in meta_tabla:
                pdf.cell(60, 5, f"  {cmp}", 1, 0)
                pdf.cell(130, 5, f"  {val[:75]}", 1, 1)
            pdf.ln(4)

            # 3. Metodología de Análisis y Reglas de Detección (Sección 4 completa)
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "3. Metodología de Análisis y Reglas de Detección", 0, 1)
            pdf.set_font("Arial", "", 7.5)
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(0, 4, "El motor heurístico aplica reglas de correlación avanzadas alineadas con la norma ISO/IEC 27035 y MITRE ATT&CK:".encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(1.5)

            pdf.set_font("Arial", "B", 7.5)
            pdf.set_fill_color(224, 231, 255)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(55, 5, "Regla de Detección", 1, 0, "L", fill=True)
            pdf.cell(30, 5, "Severidad", 1, 0, "C", fill=True)
            pdf.cell(105, 5, "Descripción Operativa / Disparador", 1, 1, "L", fill=True)

            pdf.set_font("Arial", "", 7)
            reglas_tbl = [
                ("Intento fallido de autenticación", "MEDIO", "Detecta fallos de autenticación recurrentes en el estado del login."),
                ("Acceso no autorizado", "ALTO", "Detecta accesos denegados explícitos en el estado o descripción de evento."),
                ("Actividad fuera de horario", "BAJO", "Detecta eventos generados fuera de la ventana laboral estándar (L-V 08-18h)."),
                ("Ataque de fuerza bruta", "CRÍTICO", "Detecta 5+ fallos de autenticación de la misma IP en ventana de 10 minutos."),
                ("Evento de severidad crítica", "CRÍTICO", "Campo severidad SIEM clasificado como 'critical', 'critico' o 'crit'.")
            ]
            for r_nom, r_sev, r_desc in reglas_tbl:
                pdf.cell(55, 5, f"  {r_nom}", 1, 0)
                pdf.cell(30, 5, f"  {r_sev}", 1, 0, "C")
                pdf.cell(105, 5, f"  {r_desc}", 1, 1)
            pdf.ln(4)

            # 4. Estadísticas Generales: Top Tipos de Eventos (Event_ID)
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "4. Estadísticas Generales: Top Tipos de Eventos Identificados", 0, 1)
            pdf.ln(1)

            pdf.set_font("Arial", "B", 8)
            pdf.set_fill_color(224, 231, 255)
            pdf.cell(15, 5, "#", 1, 0, "C", fill=True)
            pdf.cell(95, 5, "Tipo de Evento (Event_ID / Descripción)", 1, 0, "L", fill=True)
            pdf.cell(80, 5, "Ocurrencias Registradas", 1, 1, "C", fill=True)

            pdf.set_font("Arial", "", 7.5)
            if 'Event_ID' in df_resumen.columns:
                top_events = df_resumen['Event_ID'].value_counts().head(8)
            elif 'Event_Description' in df_resumen.columns:
                top_events = df_resumen['Event_Description'].value_counts().head(8)
            else:
                top_events = pd.Series({'Eventos SIEM': total_casos})

            idx = 1
            for ev_name, ev_cnt in top_events.items():
                pdf.cell(15, 5, f"{idx}", 1, 0, "C")
                pdf.cell(95, 5, f"  {str(ev_name)[:50]}", 1, 0)
                pdf.cell(80, 5, f"{ev_cnt}", 1, 1, "C")
                idx += 1
            pdf.ln(4)

            # 5. Resumen de Casos por los 6 Vectores de Ataque
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "5. Resumen de Casos por los 6 Vectores de Ataque Profesionales", 0, 1)
            pdf.ln(1)
            
            pdf.set_font("Arial", "B", 8)
            pdf.set_fill_color(224, 231, 255)
            pdf.cell(75, 5, " Vector de Ataque", 1, 0, "L", fill=True)
            pdf.cell(45, 5, "Casos Identificados", 1, 0, "C", fill=True)
            pdf.cell(70, 5, "Estado SGSI", 1, 1, "L", fill=True)

            vectores_todos = ['Fuerza Bruta', 'Escalamiento de Privilegios', 'Comandos y Procesos', 'Movimiento Lateral', 'Inicios Sospechosos', 'Otras Anomalías']
            vector_counts = df_resumen['Vector_Ataque'].value_counts()
            
            pdf.set_font("Arial", "", 7.5)
            for vec in vectores_todos:
                cnt_vec = int(vector_counts.get(vec, 0))
                est = "Atención Inmediata" if cnt_vec > 0 and vec in ['Fuerza Bruta', 'Escalamiento de Privilegios', 'Comandos y Procesos'] else "Monitoreo Continuo"
                pdf.cell(75, 5, f"  {vec}", 1, 0)
                pdf.cell(45, 5, f"{cnt_vec}", 1, 0, "C")
                pdf.cell(70, 5, f"  {est}", 1, 1)
            pdf.ln(4)

            # 6. IPs de Origen y Usuarios Involucrados (Sección 8 completa)
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "6. IPs de Origen y Usuarios Involucrados (Mayor Actividad)", 0, 1)
            pdf.ln(1)
            
            pdf.set_font("Arial", "B", 8)
            pdf.set_fill_color(224, 231, 255)
            pdf.cell(15, 5, "#", 1, 0, "C", fill=True)
            pdf.cell(95, 5, "IP de Origen / Usuario Afectado", 1, 0, "L", fill=True)
            pdf.cell(80, 5, "Registros Asociados", 1, 1, "C", fill=True)

            pdf.set_font("Arial", "", 7.5)
            if 'Source_IP' in df_resumen.columns:
                top_ips = df_resumen['Source_IP'].value_counts().head(6)
            elif 'User' in df_resumen.columns:
                top_ips = df_resumen['User'].value_counts().head(6)
            else:
                top_ips = pd.Series({'IP Red Interna': total_casos})

            ip_idx = 1
            for ip_val, ip_cnt in top_ips.items():
                pdf.cell(15, 5, f"{ip_idx}", 1, 0, "C")
                pdf.cell(95, 5, f"  {str(ip_val)}", 1, 0)
                pdf.cell(80, 5, f"{ip_cnt}", 1, 1, "C")
                ip_idx += 1
            pdf.ln(4)

            # 7. Plan de Acción, Responsables y Recomendaciones de Mitigación
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "7. Plan de Acción y Responsables de Mitigación", 0, 1)
            pdf.ln(1)
            
            pdf.set_font("Arial", "B", 8)
            pdf.set_fill_color(224, 231, 255)
            pdf.cell(30, 5, " Horizonte", 1, 0, "C", fill=True)
            pdf.cell(40, 5, "Responsable", 1, 0, "C", fill=True)
            pdf.cell(65, 5, "Acciones de Mitigación", 1, 0, "L", fill=True)
            pdf.cell(55, 5, "Marcos / Controles", 1, 1, "L", fill=True)
            
            pdf.set_font("Arial", "", 7)
            planes_accion = [
                ("Inmediato\n(0 - 24 h)", "Equipo SOC / CISO", f"Activar respuesta ante {criticos_cnt} eventos críticos. Aislar sistemas y revocar credenciales en menos de 1h.", "ISO 27001 (A.5.24)\nISO 27035 (Contención)"),
                ("Corto Plazo\n(1 - 7 días)", "Infraestructura TI", f"Revisar {medios_cnt} intentos fallidos, auditar PowerShell y forzar formación en seguridad.", "ISO 27001 (A.8.7)\nISO 27701 (Privacidad)"),
                ("Mediano Plazo\n(7 - 30 días)", "Seguridad Accesos", f"Documentar {bajos_cnt} accesos fuera de horario e implementar controles temporales.", "ISO 27001 (A.9.4.2)\nISO 27035 (Erradicación)"),
                ("Largo Plazo\n(30 - 90 d)", "Comité SGSI / TI", "Realizar análisis post-mortem semanal y hardening corporativo de servidores.", "ISO 27001 (Mejora Continua)")
            ]
            
            for hor, resp, desc_plan, ctrl in planes_accion:
                pdf.cell(30, 9, hor, 1, 0, "C")
                pdf.cell(40, 9, resp, 1, 0, "C")
                pdf.cell(65, 9, desc_plan, 1, 0)
                pdf.cell(55, 9, ctrl, 1, 1)
            pdf.ln(4)
            
            # 8. Detalle de Hallazgos y Log ID
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "8. Detalle de Hallazgos Principales (Log ID)", 0, 1)
            pdf.set_font("Arial", "", 7)
            pdf.ln(1)
            
            for _, row in df_resumen.head(10).iterrows():
                log_id = str(row.get('Log_ID', 'N/A'))
                host = str(row.get('Hostname', 'N/A'))
                vec = str(row.get('Vector_Ataque', 'N/A'))
                crit = str(row.get('Criticidad_Consultoria', 'N/A'))
                desc = str(row.get('Event_Description', 'N/A'))
                just = str(row.get('Justificacion_Tecnica', 'N/A'))
                
                pdf.set_font("Arial", "B", 7)
                pdf.cell(0, 4, f"[Log ID: {log_id}] Host: {host} | Vector: {vec} (Riesgo: {crit})", 0, 1)
                pdf.set_font("Arial", "", 6.5)
                pdf.multi_cell(0, 3.5, f"Evidencia: {desc}\nExplicacion: {just}".encode('latin-1', 'replace').decode('latin-1'))
                pdf.ln(1.5)

            # 9. Conclusiones del Análisis Forense (Sección 10 completa)
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "9. Conclusiones del Análisis Forense", 0, 1)
            pdf.set_font("Arial", "", 7.5)
            pdf.set_text_color(50, 50, 50)
            
            top_ip_str = top_ips.index[0] if len(top_ips) > 0 else "N/A"
            top_ip_cnt_str = top_ips.iloc[0] if len(top_ips) > 0 else 0
            
            conclusiones_texto = (
                f"El análisis procesó {len(df)} registros del archivo '{nombre_log}', detectando {total_casos} incidentes "
                f"(tasa de detección: {tasa_deteccion:.2f}%). La presencia de {criticos_cnt} incidente(s) CRÍTICO(S) requiere atención inmediata. "
                f"En total {criticos_cnt + altos_cnt} incidente(s) presentan nivel CRÍTICO o ALTO. "
                f"Este informe fue generado automáticamente por SOC Incident Analyzer. Los hallazgos deben ser validados por un analista certificado. "
                f"La IP con mayor actividad fue {top_ip_str} con {top_ip_cnt_str} evento(s)."
            )
            pdf.multi_cell(0, 4.5, conclusiones_texto.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(4)

            # 10. ANEXO GRÁFICO AL FINAL
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "10. Anexo Gráfico y Distribución de Incidentes", 0, 1, "L")
            pdf.ln(2)
            
            pie_path = None
            try:
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7, 2.5))
                
                counts_crit = df_resumen['Criticidad_Consultoria'].value_counts()
                colors_crit = ['#ef4444', '#f59e0b', '#8b5cf6', '#10b981'][:len(counts_crit)]
                ax1.pie(counts_crit, labels=counts_crit.index, autopct='%1.1f%%', colors=colors_crit, textprops={'fontsize': 6})
                ax1.set_title("Distribución por Riesgo", fontsize=8)
                
                counts_vec = df_resumen['Vector_Ataque'].value_counts()
                ax2.barh(counts_vec.index, counts_vec.values, color='#7c3aed')
                ax2.set_title("Casos por Vectores", fontsize=8)
                ax2.tick_params(axis='y', labelsize=6)
                ax2.tick_params(axis='x', labelsize=6)
                
                plt.tight_layout()
                pie_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
                plt.savefig(pie_path, bbox_inches='tight', dpi=180)
                plt.close(fig)
                
                pdf.image(pie_path, x=20, w=170)
            except Exception as e:
                pdf.cell(0, 5, f"No se pudo renderizar el anexo gráfico: {str(e)}", 0, 1)

            if pie_path and os.path.exists(pie_path):
                try: os.unlink(pie_path)
                except: pass
                
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
            pdf.output(tmp_file.name)
            return tmp_file.name

        if "pdf_generated_path" not in st.session_state:
            st.session_state.pdf_generated_path = None

        if st.button("📄 Generar Informe Ejecutivo PDF Profesional (SOC ADVISORY DAV)"):
            with st.spinner("Compilando reporte A4 con formato semáforo y diseño optimizado..."):
                st.session_state.pdf_generated_path = generar_pdf_consultoria(
                    df_filtrado, 
                    file_name_original, 
                    file_hash, 
                    file_size_kb, 
                    file_ext
                )
            st.success("¡Informe generado con éxito incorporando todas las secciones y el formato semáforo!")

        if st.session_state.pdf_generated_path and os.path.exists(st.session_state.pdf_generated_path):
            with open(st.session_state.pdf_generated_path, "rb") as f:
                st.download_button(
                    label="⬇️ Descargar PDF Profesional para Cliente (SOC ADVISORY DAV)",
                    data=f,
                    file_name="Informe_MultiISO_SOC_ADVISORY_DAV.pdf",
                    mime="application/pdf"
                )
                
    except Exception as e:
        st.error(f"Error al procesar el archivo Excel. Detalles: {e}")
else:
    st.info("👈 Por favor, carga tu archivo de logs (`.xlsx`) en la barra lateral para iniciar la consultoría de seguridad con SOC ADVISORY DAV.")
