class PDFReport(FPDF):
            def __init__(self):
                super().__init__(orientation='P', unit='mm', format='A4')
                self.set_auto_page_break(auto=True, margin=15)
                
            def header(self):
                # Banda superior en morado oscuro
                self.set_fill_color(30, 27, 75)
                self.rect(0, 0, 210, 14, 'F')
                self.set_font('Arial', 'B', 8.5)
                self.set_text_color(250, 204, 21) # Amarillo
                self.set_xy(10, 3)
                self.cell(100, 8, 'SOC ADVISORY DAV | INFORME TÉCNICO EJECUTIVO', 0, 0, 'L')
                self.set_xy(110, 3)
                self.cell(90, 8, 'ISO/IEC 27001:2022 COMPLIANCE', 0, 0, 'R')
                self.set_y(18) # Salto de seguridad garantizado
                
            def footer(self):
                self.set_y(-12)
                self.set_font('Arial', 'I', 7.5)
                self.set_text_color(128, 128, 128)
                self.cell(0, 8, f'Página {self.page_no()} | SOC ADVISORY DAV - Documento Confidencial', 0, 0, 'C')

        def generar_pdf_consultoria(df_resumen, nombre_log, hash_log):
            pdf = PDFReport()
            pdf.add_page()
            
            # Título principal
            pdf.set_font("Arial", "B", 11)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "INFORME DE AUDITORÍA FORENSE Y CUMPLIMIENTO SGSI", 0, 1, "L")
            pdf.set_font("Arial", "", 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4, f"Fecha de Emisión: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')} | Marco: ISO/IEC 27001:2022", 0, 1, "L")
            pdf.ln(2)
            
            # Caja Metadatos
            pdf.set_fill_color(245, 243, 255)
            y_meta = pdf.get_y()
            pdf.rect(10, y_meta, 190, 14, 'F')
            pdf.set_xy(12, y_meta + 2)
            pdf.set_font("Arial", "B", 7.5)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(90, 4, f"Artefacto: {nombre_log[:40]}", 0, 0)
            pdf.cell(95, 4, f"Total Registros: {len(df_resumen)}", 0, 1)
            pdf.set_x(12)
            pdf.cell(185, 4, f"Hash SHA-256: {hash_log}", 0, 1)
            
            # Salto vertical forzado para despejar metadatos
            pdf.set_y(y_meta + 17)
            
            # 1. Resumen Ejecutivo
            pdf.set_font("Arial", "B", 9)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "1. Resumen Ejecutivo y Detalle del Análisis Realizado", 0, 1)
            pdf.set_font("Arial", "", 7.5)
            pdf.set_text_color(50, 50, 50)
            resumen_texto = (
                f"Mediante SOC ADVISORY DAV, se completó la auditoría forense sobre el archivo '{nombre_log}'. "
                f"Se detectaron {criticos_cnt} eventos críticos y {altos_cnt} anomalías operativas. "
                f"El análisis coteja la telemetría con controles normativos para mitigar desvíos del SGSI."
            )
            pdf.multi_cell(0, 3.8, resumen_texto.encode('latin-1', 'replace').decode('latin-1'))
            pdf.ln(2)
            
            # 2. Gráfico Estadístico (Posicionamiento Absoluto Calculado)
            pie_path = None
            try:
                pdf.set_font("Arial", "B", 9)
                pdf.set_text_color(30, 27, 75)
                pdf.cell(0, 5, "2. Análisis Estadístico y Distribución de Riesgos", 0, 1)
                
                fig, ax = plt.subplots(figsize=(3.5, 1.4))
                counts = df_resumen['Criticidad_Consultoria'].value_counts()
                chart_colors = ['#eab308', '#a855f7', '#7c3aed', '#6b21a8'][:len(counts)]
                ax.pie(counts, labels=counts.index, autopct='%1.1f%%', colors=chart_colors, textprops={'fontsize': 6})
                
                pie_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
                plt.savefig(pie_path, bbox_inches='tight', dpi=180)
                plt.close(fig)
                
                img_y_start = pdf.get_y() + 1
                pdf.image(pie_path, x=65, y=img_y_start, w=75)
                
                # CORRECCIÓN CLAVE: Desplazar Y manualmente debajo del alto de la imagen (28 mm)
                pdf.set_y(img_y_start + 30)
            except Exception:
                pdf.ln(2)

            if pie_path and os.path.exists(pie_path):
                try: os.unlink(pie_path)
                except: pass

            # 3. Plan de Acción e ISO 27001
            pdf.set_font("Arial", "B", 9)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "3. Plan de Acción, Tiempos y Controles ISO/IEC 27001", 0, 1)
            pdf.ln(1)
            
            pdf.set_font("Arial", "B", 7)
            pdf.set_fill_color(230, 225, 250)
            pdf.cell(40, 4.5, "Plazo / Horizonte", 1, 0, "C", fill=True)
            pdf.cell(85, 4.5, "Acciones de Mitigación / Medida", 1, 0, "C", fill=True)
            pdf.cell(65, 4.5, "Control ISO 27001:2022", 1, 1, "C", fill=True)
            
            pdf.set_font("Arial", "", 6.5)
            pdf.cell(40, 4.5, "Inmediato (0 - 24 h)", 1, 0)
            pdf.cell(85, 4.5, "Aislamiento de hosts y revocación de credenciales.", 1, 0)
            pdf.cell(65, 4.5, "Control A.5.24 (Gestión de Incidentes)", 1, 1)
            
            pdf.cell(40, 4.5, "Corto Plazo (1 - 7 días)", 1, 0)
            pdf.cell(85, 4.5, "Auditoría de comandos y hardening perimetral.", 1, 0)
            pdf.cell(65, 4.5, "Controles A.8.7 y A.8.16 (Monitoreo)", 1, 1)
            
            pdf.cell(40, 4.5, "Largo Plazo (30 - 90 días)", 1, 0)
            pdf.cell(85, 4.5, "Mínimo privilegio y automatización SIEM.", 1, 0)
            pdf.cell(65, 4.5, "Controles A.5.17 y A.9.12 (Accesos)", 1, 1)
            pdf.ln(3)
            
            # 4. Hallazgos Forenses
            pdf.set_font("Arial", "B", 9)
            pdf.set_text_color(30, 27, 75)
            pdf.cell(0, 5, "4. Principales Hallazgos Forenses (Top Registros)", 0, 1)
            pdf.set_font("Arial", "", 6.5)
            
            for _, row in df_resumen.head(8).iterrows():
                log_id = str(row.get('Log_ID', 'N/A'))
                host = str(row.get('Hostname', 'N/A'))
                crit = str(row.get('Criticidad_Consultoria', 'N/A'))
                just = str(row.get('Justificacion_Tecnica', 'N/A'))
                linea = f"[{log_id}] Host: {host} | Nivel: {crit} - {just}"
                pdf.cell(0, 3.5, linea.encode('latin-1', 'replace').decode('latin-1'), 0, 1)
                
            tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
            pdf.output(tmp_file.name)
            return tmp_file.name
