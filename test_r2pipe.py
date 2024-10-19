import r2pipe

r2 = r2pipe.open("D:/ARCHIVOS/IZHR/ESCUELA/OneDrive - Instituto Politecnico Nacional/IPN-UPIITA/10MO SEMESTRE/PT I/Proyecto/Pruebas/Ledger Live.exe")
info = r2.cmdj("ij")
print(info)
r2.quit()
