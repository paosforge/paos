form explorer spec=v1
window title=File_Explorer w=640 h=560 x=320 y=100 resizable=1 min_w=640 min_h=440 chrome=standard restore=fresh
widget type=listview id=volume x=16 y=42 w=608 h=138 text=Volume_and_copy_status role=table bind=fs.status scroll=0
widget type=listview id=drives x=16 y=188 w=148 h=352 text=Drives role=table bind=fs.drives scroll=0
widget type=listview id=files x=172 y=188 w=256 h=352 text=Files_(right_click_for_menu) role=table bind=fs.root scroll=0
widget type=listview id=details x=436 y=188 w=188 h=352 text=Details role=table bind=fs.details scroll=0
widget type=menu id=context x=172 y=48 w=232 h=232 text=Open|Up|Name|Size|Kind|Refresh|Use_for_PaOS_files bind=fs.context role=menu
widget type=menu id=drive_format x=16 y=188 w=148 h=40 text=Format bind=fs.format role=menu
