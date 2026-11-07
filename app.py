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
        # 2. MOTOR DE CORRELACIÓN: 6 VECTORES Y RIESGOS ISO 27001
        # ----------------------------------------------------
        def clasificar_vector_y_riesgo(row):
            sev = str(row.get('Severity', '')).lower()
            desc = str(row.get('Event_Description', '')).lower()
            cmd = str(row.get('Process_CommandLine', '')).lower()
            res = str(row.get('Result', '')).lower()
            event_id = str(row.get('Event_ID', ''))
            
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

            # Criticidad e Impacto ISO 27001
            if vector in ['Escalamiento de Privilegios', 'Comandos y Procesos'] and ('high' in sev or 'critical' in sev or 'powershell' in cmd):
                criticidad = 'Crítico'
                justificacion = f"Vector [{vector}]: Ejecución de código malicioso o privilegios elevados. Controles ISO 27001: A.8.7 (Malware) y A.8.16 (Monitoreo)."
            elif vector in ['Fuerza Bruta', 'Movimiento Lateral'] or 'fail' in res or 'denied' in res:
                criticidad = 'Alto'
                justificacion = f"Vector [{vector}]: Fallo de autenticación o acceso lateral relevante. Control ISO 27001: A.9.4.2 / A.5.17 (Accesos)."
            elif vector == 'Inicios Sospechosos' or 'informational' in sev:
                criticidad = 'Medio'
                justificacion = f"Vector [{vector}]: Evento operativo relevante. Trazabilidad requerida por Control ISO 27001: A.8.15 (Registro de Eventos)."
            else:
                criticidad = 'Bajo'
                justificacion = f"Vector [{vector}]: Actividad rutinaria sin impacto crítico en la infraestructura."

            return vector, criticidad, justificacion

        df_analisis = df.copy()
        resultados = df_analisis.apply(clasificar_vector_y_riesgo, axis=1)
        df_analisis['Vector_Ataque'] = [r[0] for r in resultados]
        df_analisis['Criticidad_Consultoria'] = [r[1] for r in resultados]
        df_analisis['Justificacion_Tecnica'] = [r[2] for r in resultados]

        # ----------------------------------------------------
        # 3. FILTROS INTERACTIVOS DE CONSULTORÍA
        # ----------------------------------------------------
        st.sidebar.header("⚙️ 3. Filtros de Auditoría")
        
        vectores_disponibles = df_analisis['Vector_Ataque'].unique().tolist()
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
        st.markdown("El presente análisis evalúa la telemetría y los registros de eventos de seguridad (SIEM) evaluando **los 6 Vectores de Ataque Profesionales** mediante un motor heurístico alineado con **MITRE ATT&CK** e **ISO/IEC 27001:2022**.")
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
        
        color_palette = {
            'Crítico': '#eab308',
            'Alto': '#facc15',
            'Medio': '#a855f7',
            'Bajo': '#6b21a8'
        }

        # Gráficos interactivos en la interfaz: Pastel de Criticidad (con conteo, % y selección interactiva), Pastel de Vectores y Línea de Tiempo
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
            
            # Capturar evento de selección en el pastel de criticidad para mostrar los Log ID asociados
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

        # ----------------------------------------------------
        # INTERACTIVIDAD AL HACER CLIC EN EL PASTEL (LOG ID POR RIESGO)
        # ----------------------------------------------------
        selected_risk_level = None
        if selected_point and "selection" in selected_point and "points" in selected_point["selection"]:
            points = selected_point["selection"]["points"]
            if points:
                selected_risk_level = points[0].get("label")

        if selected_risk_level:
            st.info(f"🎯 **Casos identificados al hacer clic en el Nivel de Riesgo [{selected_risk_level}]:**")
            df_selected_cases = df_filtrado[df_filtrado['Criticidad_Consultoria'] == selected_risk_level]
            
            if not df_selected_cases.empty:
                # Mostrar listado interactivo con Log_ID y detalles clave
                st.dataframe(
                    df_selected_cases[['Log_ID', 'Timestamp', 'Hostname', 'User', 'Vector_Ataque', 'Event_Description', 'Justificacion_Tecnica']],
                    use_container_width=True
                )
            else:
                st.write("No hay registros para este nivel de riesgo con el filtro actual.")

        # ----------------------------------------------------
        # GUÍA MATRIZ DE RIESGO Y HALLAZGOS FORENSES
        # ----------------------------------------------------
        with st.expander("ℹ️ Guía Ejecutiva: Interpretación de Niveles de Riesgo y Medidas ISO 27001"):
            st.markdown("""
            ### 🚨 1. Riesgo Crítico (Respuesta Inmediata: 0 - 24 h)
            * **Implica:** Evidencia clara de compromiso de activos, ejecución remota de código o escalamiento de privilegios.
            * **Medidas ISO 27001:** **A.5.24 (Gestión de Incidentes)** y **A.8.7 (Protección contra Malware)**.

            ### ⚠️ 2. Riesgo Alto (Respuesta a Corto Plazo: 1 - 7 días)
            * **Implica:** Fuerza bruta o movimiento lateral detectado en la red.
            * **Medidas ISO 27001:** **A.5.17 (Autenticación)** y **A.8.16 (Monitoreo)**.

            ### 🟣 3. Riesgo Medio (Respuesta a Mediano Plazo: 7 - 30 días)
            * **Implica:** Inicios sospechosos u operaciones administrativas relevantes.
            * **Medidas ISO 27001:** **A.8.15 (Registro de Eventos)**.

            ### 🟢 4. Riesgo Bajo (Monitoreo Continuo)
            * **Implica:** Actividad rutinaria dentro de la línea base esperada.
            * **Medidas ISO 27001:** **A.8.16 (Actividad de Monitoreo)**.
            """)

        # ----------------------------------------------------
        # 6. MATRIZ DETALLADA Y FILTRO POR LOG ID Y JUSTIFICACIÓN
        # ----------------------------------------------------
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

        # ----------------------------------------------------
        # 7. GENERACIÓN DE INFORME PDF PROFESIONAL CON FLUJO CONTINUO
        # ----------------------------------------------------
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
                self.cell(100, 8, 'SOC ADVISORY DAV | INFORME TÉCNICO EJECUTIVO', 0, 0, 'L')
                self.set_xy(110, 4)
                self.cell(90, 8, 'ISO/IEC 27001:2022 COMPLIANCE', 0, 0, 'R')
                self.ln(20)
                
            def footer(self):
                self.set_y(-12)
                self.set_font('Arial', 'I', 7.5)
                self.set_text_color(128, 128, 128)
                self.cell(0, 8, f'Página {self.page_no()} | SOC ADVISORY DAV - Documento Confidencial', 0, 0, 'C')

        def generar_pdf_consultoria(df_resumen, nombre_log, hash_log):
            pdf = PDFReport()
            pdf.add_page()
            
            pdf.set_font("Arial", "B", 12)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 6, "INFORME DE AUDITORÍA FORENSE Y CUMPLIMIENTO SGSI", 0, 1, "L")
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4, f"Fecha de Emisión: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')} | Marco: ISO/IEC 27001:2022", 0, 1, "L")
            pdf.ln(2)
            
            # Metadata Box
            pdf.set_fill_color(245, 243, 255)
            y_meta = pdf.get_y()
            pdf.rect(10, y_meta, 190, 15, 'F')
            pdf.set_xy(12, y_meta + 2)
            pdf.set_font("Arial", "B", 7.5)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(90, 4, f"Artefacto: {nombre_log[:45]}", 0, 0)
            pdf.cell(95, 4, f"Total Casos Analizados: {len(df_resumen)} (Críticos: {criticos_cnt}, Altos: {altos_cnt}, Medios: {medios_cnt}, Bajos: {bajos_cnt})", 0, 1)
            pdf.set_x(12)
            pdf.cell(185, 4, f"Hash SHA-256: {hash_log}", 0, 1)
            pdf.set_y(y_meta + 18)
            
            # 1. Resumen Ejecutivo y Casos divididos por riesgos
            pdf.set_font("Arial", "B", 9)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "1. Resumen Ejecutivo y Desglose de Casos por Riesgos", 0, 1)
            pdf.set_font("Arial", "", 7.5)
            pdf.set_text_color(50, 50, 50)
            resumen_texto = f"Mediante SOC ADVISORY DAV, se completó la auditoría forense sobre '{nombre_log}'. Se analizaron un total de {len(df_resumen)} casos divididos por niveles de riesgo: {criticos_cnt} Críticos, {altos_cnt} Altos, {medios_cnt} Medios y {bajos_cnt} Bajos. El análisis evalúa los 6 Vectores de Ataque Profesionales para garantizar el control y mitigación de desvíos del SGSI."
            pdf.multi_cell(0, 4, resumen_texto.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(2)
            
            # 2. Resumen por Vectores de Ataque
            pdf.set_font("Arial", "B", 9)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "2. Resumen de Casos y Métricas por los 6 Vectores de Ataque", 0, 1)
            pdf.set_font("Arial", "", 7.5)
            vector_counts = df_resumen['Vector_Ataque'].value_counts()
            for vec, count in vector_counts.items():
                pdf.cell(0, 4, f"- Vector [{vec}]: {count} casos identificados.", 0, 1)
            pdf.ln(2)

            # 3. Plan de Acción y Recomendaciones
            pdf.set_font("Arial", "B", 9)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "3. Plan de Acción y Recomendaciones de Seguridad Corporativa", 0, 1)
            pdf.ln(1)
            
            pdf.set_font("Arial", "B", 7.5)
            pdf.set_fill_color(230, 225, 250)
            pdf.cell(40, 5, "Horizonte", 1, 0, "C", fill=True)
            pdf.cell(85, 5, "Acciones de Mitigación / Medida", 1, 0, "C", fill=True)
            pdf.cell(65, 5, "Control ISO 27001:2022", 1, 1, "C", fill=True)
            
            pdf.set_font("Arial", "", 7)
            pdf.cell(40, 5, "Inmediato (0 - 24 h)", 1, 0)
            pdf.cell(85, 5, "Aislamiento de hosts y revocación de credenciales comprometidas.", 1, 0)
            pdf.cell(65, 5, "Control A.5.24 (Gestión de Incidentes)", 1, 1)
            
            pdf.cell(40, 5, "Corto Plazo (1 - 7 días)", 1, 0)
            pdf.cell(85, 5, "Auditoría de comandos y mitigación perimetral (RDP/SMB).", 1, 0)
            pdf.cell(65, 5, "Controles A.8.7 y A.8.16 (Monitoreo)", 1, 1)
            
            pdf.cell(40, 5, "Largo Plazo (30 - 90 días)", 1, 0)
            pdf.cell(85, 5, "Principio de mínimo privilegio y automatización SIEM.", 1, 0)
            pdf.cell(65, 5, "Controles A.5.17 y A.9.12 (Accesos)", 1, 1)
            pdf.ln(2)
            
            # 4. Detalle de Hallazgos, Log ID y Evidencias
            pdf.set_font("Arial", "B", 9)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "4. Detalle de Hallazgos, Log ID, Evidencias y Explicación Técnica", 0, 1)
            pdf.set_font("Arial", "", 6.5)
            
            for _, row in df_resumen.head(15).iterrows():
                log_id = str(row.get('Log_ID', 'N/A'))
                host = str(row.get('Hostname', 'N/A'))
                vec = str(row.get('Vector_Ataque', 'N/A'))
                crit = str(row.get('Criticidad_Consultoria', 'N/A'))
                desc = str(row.get('Event_Description', 'N/A'))
                just = str(row.get('Justificacion_Tecnica', 'N/A'))
                
                linea = f"[Log ID: {log_id}] Host: {host} | Vector: {vec} (Riesgo: {crit})\n Evidencia: {desc}\n Explicacion: {just}"
                pdf.multi_cell(0, 3.5, linea.encode('latin-1', 'replace').decode('latin-1'))
                pdf.ln(1)

            # 5. ANEXO GRÁFICO AL FINAL (Continuo y optimizado sin espacio vacío)
            pdf.ln(2)
            pdf.set_font("Arial", "B", 10)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 6, "5. Anexo Gráfico y Distribución de Incidentes", 0, 1, "L")
            pdf.ln(1)
            
            pie_path = None
            try:
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7, 2.5))
                
                # Gráfico 1: Pastel de Riesgos (Criticidad)
                counts_crit = df_resumen['Criticidad_Consultoria'].value_counts()
                colors_crit = ['#eab308', '#facc15', '#a855f7', '#6b21a8'][:len(counts_crit)]
                ax1.pie(counts_crit, labels=counts_crit.index, autopct='%1.1f%%', colors=colors_crit, textprops={'fontsize': 6})
                ax1.set_title("Distribución por Nivel de Riesgo", fontsize=8)
                
                # Gráfico 2: Casos por los 6 Vectores de Ataque
                counts_vec = df_resumen['Vector_Ataque'].value_counts()
                ax2.barh(counts_vec.index, counts_vec.values, color='#7c3aed')
                ax2.set_title("Casos por Vectores de Ataque", fontsize=8)
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
            with st.spinner("Compilando reporte A4 corporativo sin espacios vacíos..."):
                st.session_state.pdf_generated_path = generar_pdf_consultoria(df_filtrado, file_name_original, file_hash)
            st.success("¡Informe generado con éxito bajo estándares A4 ajustados!")

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
