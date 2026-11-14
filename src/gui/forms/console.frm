form console spec=v1
window title=PaOS_Console w=760 h=560 x=120 y=100 resizable=1 min_w=520 min_h=360 chrome=tabs restore=always
widget type=console_grid id=transcript x=16 y=56 w=728 h=368 text=transcript role=log
widget type=textfield id=input x=16 y=440 w=728 h=28 text=_ role=textbox
widget type=status id=status_strip x=16 y=484 w=728 h=40 text=console_status role=status
widget type=label id=session parent=status_strip x=0 y=0 w=150 h=22 text=session=owner role=status_text
widget type=label id=verb_count parent=status_strip x=0 y=0 w=150 h=22 text=verbs=0 role=status_text
widget type=label id=last_status parent=status_strip x=0 y=0 w=180 h=22 text=last=ready role=status_text
widget type=tabstrip id=tabs x=1 y=1 w=620 h=39 text=PaOS_Console role=tablist
widget type=menu id=tab_menu x=281 y=41 w=220 h=104 text=New_Tab|Settings|About_PaOS role=menu
