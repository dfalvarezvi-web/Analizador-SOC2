import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile

# Configuración inicial de la página
st.set_page_config(
    page_title="SOC Advisory - Ciberseguridad & Threat Intel",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Centro de Operaciones de Seguridad (SOC) | Consultoría Profesional")
st.markdown("Plataforma avanzada de análisis forense, correlación de incidentes, categorización por vectores de ataque y generación de informes ejecutivos.")

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
        
        # Convertir Timestamp a formato fecha/hora de forma segura
        if 'Timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        
        st.sidebar.success("¡Logs cargados y normalizados con éxito!")
        
        with st.expander("🔍 Vista previa de registros crudos (Raw Logs)"):
            st.dataframe(df, use_container_width=True)
            
        # ----------------------------------------------------
        # 2. MOTOR DE CLASIFICACIÓN BASADO EN LOS 6 VECTORES
        # ----------------------------------------------------
        def clasificar_vector_ataque(row):
            desc = str(row.get('Event_Description', '')).lower()
            res = str(row.get('Result', '')).lower()
            cmd = str(row.get('Process_CommandLine', '')).lower()
            sev = str(row.get('Severity', '')).lower()
            event_id = str(row.get('Event_ID', ''))
            
            # 1. Fuerza Bruta
            if 'fail' in res or '4625' in event_id or 'failed' in desc or 'bad password' in desc:
                return 'Fuerza Bruta', 'Alto', 'Intentos repetidos de autenticación fallida o credenciales incorrectas.'
            
            # 2. Escalamiento de Privilegios
            elif 'privileges' in desc or '4672' in event_id or 'administrators' in cmd or 'localgroup' in cmd:
                return 'Escalamiento de Privilegios', 'Crítico', 'Asignación de privilegios especiales o consulta de grupos administrativos en terminales.'
            
            # 3. Comandos y Procesos
            elif 'powershell' in cmd or 'cmd.exe' in cmd or 'process' in desc or '4688' in event_id or 'archive' in desc:
                if 'powershell' in cmd or 'archive' in desc:
                    return 'Comandos y Procesos', 'Crítico', 'Ejecución de scripts avanzados (PowerShell) o empaquetado sospechoso de archivos.'
                else:
                    return 'Comandos y Procesos', 'Medio', 'Creación de procesos estándar supervisados en el sistema operativo.'
            
            # 4. Movimiento Lateral
            elif 'rdp' in desc or 'logontype=10' in desc or '5140' in event_id or 'share' in desc or 'lateral' in desc:
                return 'Movimiento Lateral', 'Alto', 'Conexiones remotas RDP o acceso a recursos compartidos de red (SMB/Shares).'
            
            # 5. Inicios Sospechosos
            elif 'logontype=3' in desc or 'success' in res and ('logon' in desc or '4624' in event_id):
                return 'Inicios Sospechosos', 'Medio', 'Inicio de sesión exitoso con patrones de origen o red específicos.'
            
            # 6. Otras Anomalías
            else:
                if 'high' in sev or 'critical' in sev:
                    return 'Otras Anomalías', 'Crítico', 'Comportamiento anómalo clasificado con severidad alta por el SIEM.'
                elif 'warning' in sev or 'medium' in sev:
                    return 'Otras Anomalías', 'Medio', 'Advertencia operativa o desviación menor de los parámetros normales.'
                else:
                    return 'Otras Anomalías', 'Bajo', 'Actividad operativa rutinaria sin impacto crítico.'

        df_analisis = df.copy()
        resultados = df_analisis.apply(clasificar_vector_ataque, axis=1)
        df_analisis['Vector_Ataque'] = [r[0] for r in resultados]
        df_analisis['Criticidad'] = [r[1] for r in resultados]
        df_analisis['Explicacion_Tecnica'] = [r[2] for r in resultados]

        # ----------------------------------------------------
        # 3. FILTROS INTERACTIVOS DE CONSULTORÍA
        # ----------------------------------------------------
        st.sidebar.header("⚙️ 3. Filtros de Auditoría")
        vectores_sel = st.sidebar.multiselect(
            "Filtrar por Vector de Ataque:",
            options=df_analisis['Vector_Ataque'].unique().tolist(),
            default=df_analisis['Vector_Ataque'].unique().tolist()
        )
        
        severidades_sel = st.sidebar.multiselect(
            "Filtrar por Criticidad:",
            options=['Crítico', 'Alto', 'Medio', 'Bajo'],
            default=['Crítico', 'Alto', 'Medio', 'Bajo']
        )
        
        df_filtrado = df_analisis[
            (df_analisis['Vector_Ataque'].isin(vectores_sel)) &
            (df_analisis['Criticidad'].isin(severidades_sel))
        ]

        # ----------------------------------------------------
        # 4. DASHBOARD DE CONTROL Y MÉTRICAS
        # ----------------------------------------------------
        st.header("📊 4. Dashboard de Control y Frecuencia de Incidentes")
        
        total_logs = len(df_filtrado)
        criticos_cnt = len(df_filtrado[df_filtrado['Criticidad'] == 'Crítico'])
        altos_cnt = len(df_filtrado[df_filtrado['Criticidad'] == 'Alto'])
        hosts_afectados = df_filtrado['Hostname'].nunique() if 'Hostname' in df_filtrado.columns else 0
        
        # Alertas dinámicas en tiempo real
        if criticos_cnt > 0:
            st.error(f"🚨 **ALERTA CRÍTICA:** Se detectaron {criticos_cnt} eventos con vectores de riesgo crítico (Escalamiento de privilegios o Comandos maliciosos). Se exige contención inmediata.")
        elif altos_cnt > 0:
            st.warning(f"⚠️ **ADVERTENCIA DE SEGURIDAD:** Se registran {altos_cnt} eventos de nivel alto asociados a Fuerza Bruta o Movimiento Lateral.")
        else:
            st.success("✅ **ESTADO CONTROLADO:** El filtrado actual no muestra anomalías críticas activas.")

        # Métricas principales
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Casos Analizados", total_logs)
        col2.metric("Incidentes Críticos", criticos_cnt, delta_color="inverse")
        col3.metric("Incidentes Altos", altos_cnt)
        col4.metric("Sistemas Afectados", hosts_afectados)
        
        # Gráficos Interactivos
        col_g1, col_g2 = st.columns(2)
        
        with col_g1:
            fig_bar = px.bar(
                df_filtrado.groupby('Vector_Ataque').size().reset_index(name='Casos'),
                x='Vector_Ataque',
                y='Casos',
                title='Número de Casos por Vector de Ataque',
                color='Vector_Ataque',
                color_discrete_sequence=px.colors.qualitative.Set2
            )
            st.plotly_chart(fig_bar, use_container_width=True)
            
        with col_g2:
            if 'Timestamp' in df_filtrado.columns and not df_filtrado.empty:
                df_freq = df_filtrado.dropna(subset=['Timestamp']).copy()
                if not df_freq.empty:
                    df_freq['Time_Group'] = df_freq['Timestamp'].dt.floor('h')
                    df_freq_grouped = df_freq.groupby(['Time_Group', 'Vector_Ataque']).size().reset_index(name='Frecuencia')
                    fig_time = px.line(
                        df_freq_grouped, 
                        x='Time_Group', 
                        y='Frecuencia', 
                        color='Vector_Ataque',
                        title='Frecuencia Temporal de Incidentes (Línea de Tiempo)'
                    )
                    st.plotly_chart(fig_time, use_container_width=True)

        # ----------------------------------------------------
        # 5. MATRIZ DE HALLAZGOS Y EVIDENCIAS
        # ----------------------------------------------------
        st.header("📋 5. Detalle de Hallazgos, Evidencias y Explicación Técnica")
        columnas_vista = [col for col in ['Log_ID', 'Timestamp', 'Hostname', 'User', 'Source_IP', 'Event_ID', 'Event_Description', 'Vector_Ataque', 'Criticidad', 'Explicacion_Tecnica'] if col in df_filtrado.columns]
        st.dataframe(df_filtrado[columnas_vista], use_container_width=True)

        # ----------------------------------------------------
        # 6. EXPORTACIÓN DEL INFORME PROFESIONAL EN PDF (PARA CLIENTE)
        # ----------------------------------------------------
        st.header("📥 6. Exportación de Entregable Ejecutivo y Técnico (PDF)")
        
        def generar_pdf_consultoria(df_resumen):
            pdf = FPDF()
            pdf.add_page()
            
            # Encabezado
            pdf.set_font("Arial", "B", 13)
            pdf.cell(0, 7, "INFORME TECNICO Y EJECUTIVO DE CONSULTORIA SOC", 0, 1, "C")
            pdf.set_font("Arial", "I", 8)
            pdf.cell(0, 5, "Analisis Forense, Vectores de Ataque, Plan de Accion y Recomendaciones", 0, 1, "C")
            pdf.ln(4)
            
            # Resumen de Casos por Vector
            pdf.set_font("Arial", "B", 9)
            pdf.cell(0, 6, "1. Resumen de Casos y Metricas por Vector de Ataque", 0, 1)
            pdf.set_font("Arial", "", 8)
            
            resumen_vectores = df_resumen['Vector_Ataque'].value_counts()
            for vec, count in resumen_vectores.items():
                pdf.cell(0, 5, f"- Vector [{vec}]: {count} casos identificados.", 0, 1)
            pdf.ln(3)
            
            # Plan de Acción y Recomendaciones Enfocadas
            pdf.set_font("Arial", "B", 9)
            pdf.cell(0, 6, "2. Plan de Accion y Recomendaciones Enfocadas", 0, 1)
            pdf.set_font("Arial", "", 8)
            plan_texto = (
                "a) Mitigacion de Fuerza Bruta: Implementar politicas de bloqueo de cuentas tras intentos fallidos y forzar MFA.\n"
                "b) Control de Inicios y Movimiento Lateral: Auditar accesos RDP y restringir permisos sobre recursos compartidos SMB.\n"
                "c) Bloqueo de Escalamiento y Comandos: Restringir la ejecucion de scripts PowerShell no firmados y auditar grupos administrativos.\n"
                "d) Contencion de Endpoints: Aislar preventivamente los equipos comprometidos detectados en los logs."
            )
            pdf.multi_cell(0, 4, plan_texto.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(3)
            
            # Detalle de Hallazgos y Evidencias
            pdf.set_font("Arial", "B", 9)
            pdf.cell(0, 6, "3. Detalle de Hallazgos, Evidencias y Explicacion Tecnica", 0, 1)
            pdf.set_font("Arial", "", 7)
            
            for index, row in df_resumen.head(20).iterrows():
                log_id = str(row.get('Log_ID', 'N/A'))
                host = str(row.get('Hostname', 'N/A'))
                vec = str(row.get('Vector_Ataque', 'N/A'))
                crit = str(row.get('Criticidad', 'N/A'))
                desc = str(row.get('Event_Description', 'N/A'))
                expl = str(row.get('Explicacion_Tecnica', 'N/A'))
                
                linea = f"[{log_id}] Host: {host} | Vector: {vec} ({crit})\n Evidencia: {desc}\n Explicacion: {expl}"
                pdf.multi_cell(0, 4, linea.encode('latin-1', 'replace').decode('latin-1'))
                pdf.ln(2)
                
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
                        file_name="Informe_Consultoria_SOC_Enfocado.pdf",
                        mime="application/pdf"
                    )
            except Exception as pdf_err:
                st.error(f"Error generando el PDF de consultoría: {pdf_err}")
                
    except Exception as e:
        st.error(f"Error al procesar el archivo Excel. Detalles: {e}")
else:
    st.info("👈 Por favor, carga tu archivo de logs (`.xlsx`) en la barra lateral para iniciar el análisis enfocado.")
