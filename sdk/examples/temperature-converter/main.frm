form temperature spec=v1
window title=Temperature_converter x=120 y=120 w=440 h=240 min_w=440 min_h=240 resizable=0 chrome=standard restore=never
widget type=label id=hint x=16 y=44 w=400 h=24 text=Enter_whole_degrees_Fahrenheit role=label
widget type=textfield id=fahrenheit x=16 y=80 w=160 h=28 text=212 role=textbox
widget type=button id=convert x=192 y=80 w=112 h=32 text=Convert role=button on_click=CONVERT
widget type=button id=restore x=312 y=80 w=112 h=32 text=Restore role=button on_click=RESTORE
widget type=label id=result x=16 y=132 w=400 h=24 text=No_conversion_yet role=label
