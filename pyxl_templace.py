from openpyxl_templates import TemplatedWorkbook
from openpyxl_templates.table_sheet import TableSheet
from openpyxl_templates.table_sheet.columns import CharColumn, IntColumn


class Table_Sheet(TableSheet):
    affects_url = CharColumn()
    severity = IntColumn()
    criticality = IntColumn()
    affects_detail = CharColumn()
    vt_name = CharColumn()
    last_seen = CharColumn()
    status = CharColumn()


class TableTemplatedWorkbook(TemplatedWorkbook):
    table_sheet_element = Table_Sheet()

def write_slsx(vulns):
    wb = TableTemplatedWorkbook()
    wb.table_sheet_element.write(
        objects=(
            (i['affects_url'], i['severity'], i['criticality'], i['affects_detail'], i['vt_name'], i['last_seen'],
             i['status'])
            for i in vulns.get('vulnerabilities')
        )
    )
    wb.save("file_scan.xlsx")


