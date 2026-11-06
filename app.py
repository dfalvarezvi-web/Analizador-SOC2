import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile

# Configuración inicial de la página
st.set_page_config(
    page_title="SOC Advisory - Auditoría y Ciberseguridad",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Centro de Operaciones de Seguridad (SOC) | Consultoría Profesional")
st.markdown("Plataforma avanzada de análisis forense, correlación de eventos, análisis temporal y gestión de incidentes para clientes corporativos.")

# ----------------------------------------------------
# 1. CARGA Y NORMALIZACIÓN DE DATOS
# ----------------------------------------------------
st.sidebar.header("📁 1. Ingesta de Logs (SIEM)")
uploaded_file = st.sidebar.file_uploader("Subir archivo de registros (.xlsx)", type=["xlsx"])

if uploaded_file is not None:
    try:
        df = pd.read_excel(uploaded_file)
        
        # Normalizar nombres de columnas (quitar espacios)
        df.columns = df.columns.astype(str).str.strip()
        
        # Convertir Timestamp a formato fecha/hora
        if 'Timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'])
            df['Hour'] = df['Timestamp'].dt.floor('H')
        
        st.sidebar.success("¡Logs cargados y normalizados con éxito!")
        
        with st.expander("🔍 Vista previa de registros crudos (Raw Logs)"):
            st.dataframe(df, use_container_width=True)
            
        # ----------------------------------------------------
        # 2. MOTOR DE CORRELACIÓN Y ANÁLISIS DE RIESGO
        # ----------------------------------------------------
        def clasificar_incidente(row):
            sev = str(row.get('Severity', '')).lower()
            desc = str(row.get('Event_Description', '')).lower()
            cmd = str(row.get('Process_CommandLine', '')).lower()
            res = str(row.get('Result', '')).lower()
            
            if 'high' in sev or 'critical' in sev or 'rce' in desc or 'malware' in desc or 'powershell' in cmd:
                return 'Crítico', 'Ejecución de código malicioso, comando crítico o severidad alta reportada por el SIEM.'
            elif 'medium' in sev or 'warning' in sev or 'fail' in res or 'denied' in res:
                return 'Alto', 'Fallo de autenticación reiterado, acceso denegado o anomalía de nivel medio/warning.'
            elif 'informational' in sev and ('logon' in desc or 'process' in desc):
                return 'Medio', 'Evento operativo relevante que requiere trazabilidad de usuario y host.'
            else:
                return 'Bajo', 'Actividad rutinaria sin impacto crítico en la infraestructura.'

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
        
        # Banner de Alertas en Tiempo Real (Threat Intel)
        if criticos_cnt > 0:
            st.error(f"🚨 **ALTA AMENAZA DETECTADA:** Se han identificado {criticos_cnt} eventos con nivel crítico que comprometen la integridad de los activos. Se requiere contención inmediata.")
        elif altos_cnt > 0:
            st.warning(f"⚠️ **ADVERTENCIA DE SEGURIDAD:** Se registran {altos_cnt} anomalías de nivel alto (intentos de acceso fallidos o comandos inusuales).")
        else:
            st.success("✅ **ESTADO ESTABLE:** No se detectan anomalías críticas en el filtrado actual.")

        # Métricas principales
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Registros Filtrados", total_logs)
        col2.metric("Incidentes Críticos", criticos_cnt, delta_color="inverse")
        col3.metric("Incidentes Altos", altos_cnt)
        col4.metric("Hosts Afectados", hosts_comprometidos)
        
        # Gráficos Interactivos de Frecuencia y Distribución
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
                df_freq = df_filtrado.groupby([df_filtrado['Timestamp'].dt.floor('T'), 'Criticidad_Consultoria']).size().reset_index(name='Frecuencia')
                fig_time = px.line(
                    df_freq, 
                    x='Timestamp', 
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
        # 6. GENERACIÓN DE INFORME PROFESIONAL EN PDF (PARA CLIENTE)
        # ----------------------------------------------------
        st.header("📥 6. Exportación de Entregable Ejecutivo para Cliente")
        
        def generar_pdf_consultoria(df_resumen):
            pdf = FPDF()
            pdf.add_page()
            
            # Encabezado del reporte de consultoría
            pdf.set_font("Arial", "B", 15)
            pdf.cell(0, 10, "INFORME EJECUTIVO DE CONSULTORIA SOC", 0, 1, "C")
            pdf.set_font("Arial", "I", 9)
            pdf.cell(0, 5, "Analisis de Seguridad, Correlacion de Logs y Plan de Accion", 0, 1, "C")
            pdf.ln(5)
            
            # Metadatos
            pdf.set_font("Arial", "B", 9)
            pdf.cell(0, 6, f"Fecha de emision: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}", 0, 1)
            pdf.cell(0, 6, f"Total de registros analizados: {len(df_resumen)} | Criticos: {criticos_cnt} | Altos: {altos_cnt}", 0, 1)
            pdf.ln(4)
            
            # Sección 1: Resumen Ejecutivo
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 6, "1. Resumen Ejecutivo y Evaluacion de Riesgo", 0, 1)
            pdf.set_font("Arial", "", 8)
            resumen_texto = (
                f"Durante la auditoria de registros se evaluaron {len(df_resumen)} eventos de seguridad. "
                f"Se detectaron {criticos_cnt} eventos criticos que evidencian ejecucion de comandos potencialmente maliciosos "
                f"y {altos_cnt} anomalias de autenticacion. Se recomienda aplicar medidas de mitigacion inmediata."
            )
            pdf.multi_cell(0, 4, resumen_texto.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(4)
            
            # Sección 2: Plan de Acción y Recomendaciones
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 6, "2. Plan de Accion y Mitigacion Recomendado", 0, 1)
            pdf.set_font("Arial", "", 8)
            acciones_texto = (
                "- Aislamiento preventivo de los equipos (Hosts) identificados con actividad critica.\n"
                "- Revocacion de sesiones activas y rotacion obligatoria de credenciales para usuarios comprometidos.\n"
                "- Auditoria profunda de comandos ejecutados via consola (Process_CommandLine).\n"
                "- Restriccion de accesos remotos no autorizados en las IPs de origen detectadas."
            )
            pdf.multi_cell(0, 4, acciones_texto.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(4)
            
            # Sección 3: Detalle de Hallazgos
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 6, "3. Principales Hallazgos Forenses", 0, 1)
            pdf.set_font("Arial", "", 7)
            
            for index, row in df_resumen.head(20).iterrows():
                log_id = row.get('Log_ID', 'N/A')
                host = row.get('Hostname', 'N/A')
                crit = row.get('Criticidad_Consultoria', 'N/A')
                just = row.get('Justificacion_Tecnica', 'N/A')
                linea = f"[{log_id}] Host: {host} | Nivel: {crit} - {just}"
                pdf.cell(0, 4, linea.encode('latin-1', 'replace').decode('latin-1'), 0, 1)
                
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
            pdf.output(tmp_file.name)
            return tmp_file.name

        if st.button("📄 Generar y Descargar Informe de Consultoría PDF"):
            try:
                pdf_path = generar_pdf_consultoria(df_filtrado)
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        label="⬇️ Descargar PDF Profesional para Cliente",
                        data=f,
                        file_name="Informe_Consultoria_SOC.pdf",
                        mime="application/pdf"
                    )
            except Exception as pdf_err:
                st.error(f"Error generando el PDF de consultoría: {pdf_err}")
                
    except Exception as e:
        st.error(f"Error al procesar el archivo Excel. Verifica que las columnas correspondan al formato SIEM. Detalles: {e}")
else:
    st.info("👈 Por favor, carga tu archivo de logs (`.xlsx`) en la barra lateral para iniciar la consultoría de seguridad.")
