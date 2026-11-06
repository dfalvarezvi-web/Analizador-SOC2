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
st.markdown("Plataforma interactiva adaptada automáticamente a tus registros de logs.")

# ----------------------------------------------------
# 1. CARGA DE ARCHIVOS (.xlsx)
# ----------------------------------------------------
st.sidebar.header("📁 1. Carga de Datos")
uploaded_file = st.sidebar.file_uploader("Subir archivo de logs (Excel .xlsx)", type=["xlsx"])

if uploaded_file is not None:
    try:
        df = pd.read_excel(uploaded_file)
        
        # Limpiar espacios en blanco en los nombres de las columnas
        df.columns = df.columns.astype(str).str.strip()
        
        st.success("¡Archivo de logs cargado y normalizado exitosamente!")
        
        with st.expander("🔍 Vista previa de los datos brutos"):
            st.dataframe(df, use_container_width=True)
            
        # ----------------------------------------------------
        # 2. ANÁLISIS DE SEGURIDAD Y CORRELACIÓN
        # ----------------------------------------------------
        st.header("🔎 2. Análisis de Seguridad y Correlación de Eventos")
        
        def obtener_valor(row, posibles_nombres):
            for col in df.columns:
                if col.lower().replace(" ", "").replace("_", "") in [p.lower().replace(" ", "").replace("_", "") for p in posibles_nombres]:
                    val = row.get(col)
                    if pd.notna(val):
                        return str(val)
            return "N/A"

        def clasificar_y_justificar(row):
            severity = obtener_valor(row, ['Severity', 'Severidad', 'Nivel'])
            desc = obtener_valor(row, ['DescriptionProcess', 'Description', 'Proceso', 'Desc'])
            result = obtener_valor(row, ['Result', 'Resultado', 'Estado'])
            
            sev_l = severity.lower()
            desc_l = desc.lower()
            res_l = result.lower()
            
            if 'critical' in sev_l or 'critico' in sev_l or 'rce' in desc_l or 'malware' in desc_l:
                return 'Crítico', 'Severidad alta o código malicioso detectado.'
            elif 'high' in sev_l or 'alto' in sev_l or 'fail' in res_l or 'denied' in res_l:
                return 'Alto', 'Fallo de autenticación o acceso denegado.'
            elif 'medium' in sev_l or 'medio' in sev_l or 'warning' in sev_l:
                return 'Medio', 'Advertencia o comportamiento anómalo.'
            else:
                return 'Bajo', 'Evento rutinario.'

        df_analisis = df.copy()
        resultados = df_analisis.apply(clasificar_y_justificar, axis=1)
        df_analisis['Criticidad_Calculada'] = [r[0] for r in resultados]
        df_analisis['Justificación_Tecnica'] = [r[1] for r in resultados]

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
        
        informe_texto = f"""INFORME TECNICO DE CIBERSEGURIDAD - SOC
- Fecha: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}
- Total de logs analizados: {total_eventos}
- Hallazgos: {criticos} criticos y {altos} altos."""
        st.text(informe_texto)

        # ----------------------------------------------------
        # 6. EXPORTACIÓN DEL INFORME EN PDF (Corregido para evitar errores de espacio)
        # ----------------------------------------------------
        st.header("📥 6. Exportación de Resultados")
        
        def generar_pdf(df_resumen):
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 10, "Informe Tecnico de Ciberseguridad - SOC", 0, 1, "C")
            pdf.ln(5)
            
            pdf.set_font("Arial", "", 10)
            pdf.cell(0, 8, f"Total Registros Analizados: {len(df_resumen)}", 0, 1, "L")
            pdf.ln(5)
            
            pdf.set_font("Arial", "B", 10)
            pdf.cell(0, 8, "Muestra de Eventos Detectados:", 0, 1, "L")
            pdf.set_font("Arial", "", 8)
            
            # Imprimir filas de forma simplificada y segura para el ancho del PDF
            for index, row in df_resumen.head(25).iterrows():
                crit = row.get('Criticidad_Calculada', 'N/A')
                justif = row.get('Justificación_Tecnica', 'N/A')
                linea = f"[{crit}] {justif}"
                pdf.cell(0, 6, linea.encode('latin-1', 'replace').decode('latin-1'), 0, 1)
                
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
            pdf.output(tmp_file.name)
            return tmp_file.name

        if st.button("📄 Generar y Descargar Informe PDF"):
            try:
                pdf_path = generar_pdf(df_analisis)
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        label="⬇️ Descargar PDF Oficial",
                        data=f,
                        file_name="Informe_SOC_Logs.pdf",
                        mime="application/pdf"
                    )
            except Exception as pdf_err:
                st.error(f"Error generando el PDF: {pdf_err}")
                
    except Exception as e:
        st.error(f"Error al procesar el archivo Excel. Verifica que sea un formato .xlsx válido. Detalles: {e}")
else:
    st.info("👈 Por favor, sube tu archivo Excel de logs desde la barra lateral para iniciar el análisis.")
