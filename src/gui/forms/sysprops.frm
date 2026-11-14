form sysprops spec=v1
window title=System_Properties w=500 h=520 x=720 y=80 resizable=1 min_w=420 min_h=320 chrome=standard restore=fresh
widget type=col id=root x=12 y=52 w=476 h=446 text=properties role=group
widget type=listview id=facts parent=root x=0 y=0 w=452 h=330 text=machine_facts role=table bind=sysprops.live scroll=0
