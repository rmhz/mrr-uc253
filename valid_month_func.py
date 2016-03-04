import string, re

USER_re=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

months= ['January','February']

def valid_username(username):
    return USER_re.match(username)

def valid_month(month):
    for mon in months:
        if string.upper(month)==string.upper (mon):return mon

def valid_day(day):
    try:
        inDay=int(day)
        if (inDay>0)&(inDay<32):
            return inDay
        else:
            return 'None'
    except:
        return 'None'


#print valid_day('0')

def escape_html(s):
    out_s=s.replace('&','&amp;')
    out_s=out_s.replace('>','&gt;')
    out_s=out_s.replace('<','&lt;')
    out_s=out_s.replace('"','&quot;')
    return out_s

def rot13(s):
    letter_string='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    orig_string=s
    result_string=''
    find_mark=0
    for i in range(len(orig_string)):
        find_mark=0
        for j in range(52):
            if orig_string[i]==letter_string[j]:
                find_mark=1
                if j<13:
                    result_string=result_string+letter_string[j+13]
                elif j<26:
                    result_string=result_string+letter_string[j-13]
                elif j<39:
                    result_string=result_string+letter_string[j+13]
                else:
                    result_string=result_string+letter_string[j-13]

        if find_mark==0:result_string=result_string+orig_string[i]
                

    return result_string

##print rot13("goddamn puctuation .,!?z")
##print rot13("Uryyb<obql>")

if not(valid_username('Di')): print "damn"
