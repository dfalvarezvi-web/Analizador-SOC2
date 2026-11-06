import streamlit as st
import pandas as pd
import plotly.express as px
from fpdf import FPDF
import tempfile

# Configuración inicial de la página
st.set_page_config(
    page_title="SOC - Analizador de Ciberseguridad",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Centro de Operaciones de Seguridad (SOC) - Análisis de Incidentes")
st.markdown("Plataforma interactiva adaptada a tus campos de logs para la ingesta, análisis, clasificación de riesgos y reportes.")

# ----------------------------------------------------
# 1. CARGA DE ARCHIVOS (.xlsx)
# ----------------------------------------------------
st.sidebar.header("📁 1. Carga de Datos")
uploaded_file = st.sidebar.file_uploader("Subir archivo de logs (Excel .xlsx)", type=["xlsx"])

if uploaded_file is not None:
    try:
        df = pd.read_excel(uploaded_file)
        st.success("¡Archivo de logs cargado exitosamente!")
        
        with st.expander("🔍 Vista previa de los datos brutos"):
            st.dataframe(df, use_container_width=True)
            
        # ----------------------------------------------------
        # 2. ANÁLISIS DE SEGURIDAD Y CORRELACIÓN
        # ----------------------------------------------------
        st.header("🔎 2. Análisis de Seguridad y Correlación de Eventos")
        
        def clasificar_y_justificar(row):
            # Usando tus columnas reales exactas
            severity = str(row.get('Severity', '')).lower()
            desc = str(row.get('DescriptionProcess', '')).lower()
            result = str(row.get('Result', '')).lower()
            cmd = str(row.get('CommandLine', '')).lower()
            
            if 'critical' in severity or 'critico' in severity or 'rce' in desc or 'malware' in desc:
                return 'Crítico', 'Severidad alta detectada o presencia de código malicioso / ejecución en CommandLine.'
            elif 'high' in severity or 'alto' in severity or 'fail' in result or 'denied' in result:
                return 'Alto', 'Fallo de autenticación, acceso denegado o evento marcado con severidad alta.'
            elif 'medium' in severity or 'medio' in severity or 'warning' in severity:
                return 'Medio', 'Advertencia o comportamiento anómalo detectado en el proceso.'
            else:
                return 'Bajo', 'Evento rutinario sin anomalías críticas aparentes.'

        # Aplicar el análisis al DataFrame
        df_analisis = df.copy()
        resultados = df_analisis.apply(clasificar_y_justificar, axis=1)
        df_analisis['Criticidad_Calculada'] = [r[0] for r in resultados]
        df_analisis['Justificación_Tecnica'] = [r[1] for r in resultados]

        # Mostrar tabla filtrada con tus columnas reales
        columnas_mostrar = ['Timestamp', 'HostnameEvent', 'IDUserSource', 'IPDestinationLog', 'Severity', 'Criticidad_Calculada', 'Justificación_Tecnica']
        columnas_existentes = [col for col in columnas_mostrar if col in df_analisis.columns]
        
        if columnas_existentes:
            st.dataframe(df_analisis[columnas_existentes], use_container_width=True)
        else:
            st.dataframe(df_analisis, use_container_width=True)

        # ----------------------------------------------------
        # 3. DASHBOARD INTERACTIVO
        # ----------------------------------------------------
        st.header("📊 3. Dashboard de Incidentes")
        
        col1, col2, col3, col4 = st.columns(4)
        total_eventos = len(df_analisis)
        criticos = len(df_analisis[df_analisis['Criticidad_Calculada'] == 'Crítico'])
        altos = len(df_analisis[df_analisis['Criticidad_Calculada'] == 'Alto'])
        medios_bajos = len(df_analisis[df_analisis['Criticidad_Calculada'].isin(['Medio', 'Bajo'])])
        
        col1.metric("Total Registros", total_eventos)
        col2.metric("Críticos", criticos)
        col3.metric("Altos", altos)
        col4.metric("Medios / Bajos", medios_bajos)
        
        # Gráficos con Plotly
        fig_crit = px.pie(
            df_analisis, 
            names='Criticidad_Calculada', 
            title='Distribución de Logs por Nivel de Criticidad',
            color='Criticidad_Calculada',
            color_discrete_map={'Crítico':'#ff4b4b', 'Alto':'#ffa15a', 'Medio':'#ffcc00', 'Bajo':'#00cc96'}
        )
        st.plotly_chart(fig_crit, use_container_width=True)

        # ----------------------------------------------------
        # 4. CLASIFICACIÓN DE RIESGOS DETALLADA
        # ----------------------------------------------------
        st.header("⚠️ 4. Matriz de Clasificación de Riesgos")
        risk_summary = df_analisis.groupby(['Criticidad_Calculada', 'Justificación_Tecnica']).size().reset_index(name='Cantidad')
        st.table(risk_summary)

        # ----------------------------------------------------
        # 5. INFORME TÉCNICO ESTRUCTURADO
        # ----------------------------------------------------
        st.header("📝 5. Informe Técnico Consolidado")
        
        informe_texto = f"""
        INFORME TÉCNICO DE CIBERSEGURIDAD - SOC
        
        - Fecha de generación: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}
        - Total de logs analizados: {total_eventos}
        - Resumen Ejecutivo: Se procesaron los registros recopilados, identificando {criticos} eventos críticos y {altos} eventos de alto riesgo que requieren validación urgente por parte del equipo técnico.
        - Recomendaciones:
          1. Revisar los comandos ejecutados (CommandLine) en los equipos marcados como críticos.
          2. Validar las direcciones IP de destino (IPDestinationLog) asociadas a tráficos sospechosos.
          3. Aplicar medidas de contención en cuentas de usuario comprometidas (IDUserSource).
        """
        st.markdown(informe_texto)

        # ----------------------------------------------------
        # 6. EXPORTACIÓN DEL INFORME EN PDF
        # ----------------------------------------------------
        st.header("📥 6. Exportación de Resultados")
        
        def generar_pdf(df_resumen, texto_inf):
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, "Informe Tecnico de Ciberseguridad - SOC", 0, 1, "C")
            pdf.ln(10)
            
            pdf.set_font("Arial", "", 10)
            for linea in texto_inf.split("\n"):
                pdf.multi_cell(0, 6, linea.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(5)
            
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 10, "Principales Hallazgos:", 0, 1, "L")
            pdf.set_font("Arial", "", 9)
            
            for index, row in df_resumen.head(15).iterrows():
                linea_tabla = f"[{row['Criticidad_Calculada']}] Host: {row.get('HostnameEvent', 'N/A')} - User: {row.get('IDUserSource', 'N/A')} - IP Dest: {row.get('IPDestinationLog', 'N/A')}"
                pdf.multi_cell(0, 5, linea_tabla.encode('latin-1', 'replace').decode('latin-1'))
                
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
            pdf.output(tmp_file.name)
            return tmp_file.name

        if st.button("📄 Generar y Descargar Informe PDF"):
            pdf_path = generar_pdf(df_analisis, informe_texto)
            with open(pdf_path, "rb") as f:
                st.download_button(
                    label="⬇️ Descargar PDF Oficial",
                    data=f,
                    file_name="Informe_SOC_Logs.pdf",
                    mime="application/pdf"
                )
    except Exception as e:
        st.error(f"Error al procesar el archivo Excel. Asegúrate de que las columnas coincidan. Detalles: {e}")
else:
    st.info("👈 Por favor, sube tu archivo Excel de logs desde la barra lateral para iniciar el análisis.")
