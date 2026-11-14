form explorer spec=v1
window title=File_Explorer w=900 h=600 x=320 y=100 resizable=1 min_w=900 min_h=600 chrome=standard restore=fresh
widget type=listview id=volume x=16 y=56 w=868 h=138 text=Volume_and_copy_status role=table bind=fs.status scroll=0
widget type=listview id=drives x=16 y=202 w=148 h=378 text=Drives role=table bind=fs.drives scroll=0
widget type=listview id=files x=172 y=202 w=482 h=378 text=Files_(right_click_for_menu) role=table bind=fs.root scroll=0
widget type=listview id=details x=662 y=202 w=222 h=378 text=Details role=table bind=fs.details scroll=0
widget type=menu id=context x=172 y=202 w=180 h=200 text=Open|Up|Name|Size|Kind|Refresh bind=fs.context role=menu
