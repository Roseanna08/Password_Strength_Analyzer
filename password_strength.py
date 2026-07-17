import math
import hashlib
import requests
import random
import datetime
import csv
import streamlit as st

st.set_page_config(page_title="Password Security Analyzer", page_icon="🔐")

def check_strength(password):
    l=len(password)
    le= False
    uc= False
    lc= False
    di=False
    ch= False
    reasons=[]
    
    for i in password:
        if i.isupper():
            uc= True
        
        if i.islower():
            lc= True

        if i.isdigit():
            di= True

        if i.isalnum()== False:
            ch= True
    if l>=8:
        le= True

    count= uc+lc+di+ch+le
    flags=[uc,lc,di,ch,le]

    if uc== False:
        reasons.append("No uppercase charecters used")
    if lc== False:
        reasons.append("No lower case charecters used")
    if di== False:
        reasons.append("No digits used")
    if ch== False:
        reasons.append("No special charecters used")
    if le== False :
        reasons.append("Password length should atleast be 8 charecters")

    if count==5:
        return "STRONG",reasons,flags,count
    elif count>2 and count<5 :
        return "MEDIUM",reasons,flags,count
    else:
        return "WEAK",reasons,flags,count

def entropy(password):
    l=len(password)
    count=0
    uuc= False
    llc= False
    ddi= False
    cch= False
    
    for i in password:
        if i.isupper():
            uuc= True
        if i.islower():
            llc= True
        if i.isdigit():
            ddi= True
        if i.isalnum()== False:
            cch= True
    if uuc:
        count+=26
    if llc:
        count+=26
    if ddi:
        count+=10
    if cch:
        count+=32

    if count!=0:
        en=l * math.log2(count)
    else:
        en=0
    return en

def crack_time(entropy):
    total_combinations = 2 ** entropy
    guesses_per_second = 1e9  # 1 billion guesses/sec
    seconds = total_combinations / guesses_per_second
    if seconds > 100000 * 31536000:
        return "Centuries (uncrackable)"
    elif seconds<60:
        return f"{seconds:.1f} seconds"
    elif seconds<3600:
        res=seconds/60
        return f"{res:.1f} minutes"
    elif seconds<86400:
        res=seconds/3600
        return f"{res:.1f} hours"
    elif seconds<31536000:
        res=seconds/86400
        return f"{res:.1f} days"
    else:
        res=seconds/31536000
        return f"{res:.1f} years"

def check_breach(password):
    sha1=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix=sha1[:5]
    suffix=sha1[5:]
    url = "https://api.pwnedpasswords.com/range/" + prefix
    response = requests.get(url)
    lines= response.text.splitlines()
    found = False
    for i in lines:
        hash_suffix,count=i.split(":")
        if hash_suffix==suffix:
            found = True
            no=count
    if found:
        return f"Password Breached (seen {no} times)"
    else:
        return "Password NOT Breached"

def suggest_password(password,flags):
    new_password=password
    l=len(new_password)
    if flags[0]== False:
        uppe=False
        for i in range(l):
            if new_password[i].isalpha():
                new_password=new_password[:i] + new_password[i].upper() + new_password[i+1:]
                uppe= True
                break
        if uppe== False:
            new_password += random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if flags[1]== False:
        lowe= False
        for i in range(l):
            if new_password[i].isalpha():
                new_password=new_password[:i] + new_password[i].lower() + new_password[i+1:]
                lowe= True
                break
        if lowe== False:
            new_password += random.choice("abcdefghijklmnopqrstuvwxyz")
    if flags[2]== False:
        new_password += random.choice("0123456789")
    if flags[3]== False:
        new_password += random.choice("!@#$%^&*-+=_")
    if flags[4]== False:
        while len(new_password)<8:
            new_password += random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    return new_password

def log_check(strength,entropy,breached):
    now = datetime.datetime.now()
    formatted = now.strftime("%d.%m.%Y %I:%M%p")
    try:
        f = open("history.csv", "r")
        file_exists = True
        f.close()
    except FileNotFoundError:
        file_exists = False
    f=open("history.csv","a")
    r=csv.writer(f)
    if not file_exists:
        r.writerow(["formatted","strength","entropy","breached"])
    r.writerow([formatted,strength,entropy,breached])
    f.close()

st.title("Password Strength Analyzer")

pas= st.text_input("Enter a password to analyze :")

if pas:
    
    result,reason,flags,count=check_strength(pas)
    if result == "STRONG":
        st.success(f"Strength : {result}")
    elif result == "MEDIUM":
        st.warning(f"Strength : {result}")
    else:
        st.error(f"Strength : {result}")

    st.progress(count / 5)

    with st.expander("Why this rating ?"):
        for i in reason:
            st.write(i)
        
    e=entropy(pas)
    st.write(f"**Entropy :** {e:.1f} bits")
    
    ct=crack_time(e)
    st.write(f"**Estimated crack time :** {ct}")

    try:
        s=check_breach(pas)
        st.write(s)
        if "NOT Breached" in s:
            breached = "no"
        else:
            breached = "yes"
    except Exception as err:
        st.warning("⚠️ Breach check unavailable right now (network issue). Skipping this check.")
        breached = "unknown"

    if result != "STRONG":
        sp=suggest_password(pas,flags)
        st.write(f"**Suggested strong password :** {sp}")
        
    log_check(result,e,breached)

    st.markdown("<p style='text-align: right; color: gray; font-size: 12px;'>Roseanna Robinson</p>",unsafe_allow_html=True)



