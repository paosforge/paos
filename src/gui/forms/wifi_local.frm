form wifi_local spec=v1
window title=Wi-Fi w=500 h=316 x=200 y=160 resizable=0 min_w=500 min_h=316 chrome=standard restore=never
widget type=label id=status x=24 y=48 w=452 h=24 text=Enter_network_name;_Next role=status_text
widget type=secret id=entry x=24 y=88 w=452 h=32 role=password
widget type=button id=next x=24 y=140 w=124 h=32 text=Next role=button
widget type=button id=save x=160 y=140 w=316 h=32 text=Save_and_connect role=button
widget type=button id=connect x=24 y=188 w=276 h=32 text=Connect_saved_network role=button
widget type=button id=cancel x=312 y=188 w=164 h=32 text=Cancel role=button
widget type=label id=note x=24 y=248 w=452 h=24 text=Local_owner_only;_WPA2_personal role=label
