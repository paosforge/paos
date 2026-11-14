def grab(name):
    m = re.search(r'%s\s*\[[^\]]*\]\s*=\s*\{(.*?)\};' % re.escape(name), src, re.S)
    return [int(x) for x in re.findall(r'-?\d+', m.group(1))]

tabs = grab('tabs'); tab32 = grab('tab32'); tab33 = grab('tab33')
tabindex = grab('tabindex'); g_linbits = grab('g_linbits')

