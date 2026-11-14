form demo_a spec=v1
window title=Demo_A w=360 h=260 x=100 y=100 resizable=1 min_w=160 min_h=100 chrome=standard restore=always
widget type=label id=label_a x=16 y=64 w=220 h=24 text=Panel_A role=label
widget type=button id=action_a x=16 y=104 w=120 h=32 text=Action_A role=button on_click=DEMO_ACTION
widget type=textfield id=entry_a x=150 y=104 w=190 h=28 text=_ role=textbox
