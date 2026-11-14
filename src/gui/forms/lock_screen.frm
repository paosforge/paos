form lock_screen spec=v1
window title=Sign_in w=640 h=480 x=0 y=0 resizable=0 min_w=640 min_h=480 chrome=standard restore=never
widget type=image id=wallpaper x=0 y=0 w=640 h=480 src=kat_quad16.bmp fit=cover role=image
widget type=col id=machine x=140 y=137 w=360 h=286 text= role=group
widget type=label id=identity x=200 y=157 w=280 h=24 text=Owner role=heading
widget type=label id=user_label x=160 y=207 w=240 h=20 text=Password role=label
widget type=textfield id=user x=160 y=157 w=12 h=22 text=paos role=textbox
widget type=label id=password_label x=432 y=207 w=48 h=20 text=US role=label
widget type=secret id=password x=160 y=232 w=320 h=32 role=password
widget type=button id=submit x=444 y=235 w=32 h=26 text=Sign_in role=button
widget type=label id=result x=160 y=277 w=320 h=40 text=Enter_your_password role=status
widget type=button id=forgot x=160 y=379 w=320 h=28 text=Forgot_password? role=button
widget type=label id=avatar x=160 y=157 w=28 h=28 text=O role=label
widget type=label id=clock x=140 y=37 w=360 h=32 text= role=label
widget type=label id=date x=140 y=87 w=360 h=20 text= role=label
widget type=button id=back x=160 y=379 w=320 h=28 text=Back_to_sign-in role=button
