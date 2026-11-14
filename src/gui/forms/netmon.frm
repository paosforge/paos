form netmon spec=v1
window title=Network_Monitor w=520 h=530 x=1260 y=80 resizable=1 min_w=440 min_h=300 chrome=standard restore=fresh
widget type=status id=link x=16 y=58 w=480 h=36 text=network role=status cadence=2
widget type=label id=link_value parent=link x=0 y=0 w=450 h=20 text=nic=e1000e role=status_text bind=netmon.live
widget type=listview id=counters x=16 y=96 w=480 h=126 text=Connection role=table bind=netmon.address scroll=0
widget type=listview id=members x=16 y=228 w=480 h=174 text=Members role=table bind=netmon.members scroll=0
widget type=label id=rx_label x=16 y=410 w=36 h=54 text=RX role=label
widget type=chart id=netmon_rx x=56 y=410 w=192 h=54 text=rx_rate role=img bind=netmon.rx_rate value=0 max=100 mode=sparkline
widget type=label id=tx_label x=256 y=410 w=36 h=54 text=TX role=label
widget type=chart id=netmon_tx x=296 y=410 w=192 h=54 text=tx_rate role=img bind=netmon.tx_rate value=0 max=100 mode=sparkline
widget type=button id=network_check x=16 y=472 w=140 h=32 text=Network_Check role=button
widget type=label id=network_check_result x=164 y=472 w=332 h=32 text=Not_checked_yet role=status_text
