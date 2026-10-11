import sys
sys.path.insert(0, '.')
from backend2 import analyze_text

tests = [
    ('Hindi scam', 'आपका बैंक खाता बंद हो जाएगा। तुरंत अपना OTP साझा करें।'),
    ('Hindi warning', 'अपना OTP किसी के साथ साझा न करें।'),
    ('Tamil scam', 'உங்கள் வங்கி கணக்கு முடக்கப்படும். உடனே உங்கள் OTP-ஐ பகிருங்கள்.'),
    ('Tamil warning', 'உங்கள் OTP-ஐ யாருடனும் பகிர வேண்டாம்.'),
    ('Hinglish scam', 'Aapka account block ho jayega. Turant apna OTP share karein.'),
    ('Tanglish scam', 'Ungal account block aayidum. Udane OTP anuppunga.'),
    ('OTP delivery notice EN', 'Your OTP is 482910. Use it to log in.'),
    ('Harmless', 'Congratulations on completing your project. Great work!'),
    ('Code-mixed Hindi+EN', 'Aapka account block ho jayega. Abhi apna OTP share karein.'),
]
for name, msg in tests:
    r = analyze_text(msg)
    cat = r['scam_category']
    conf = r['confidence']
    coerce = r['coercion_score']
    phrases = r['detected_phrases']
    cflags = r.get('context_flags', [])
    rflags = r.get('risk_flags', [])
    print(f'{name}:')
    print(f'  cat={cat}, conf={conf}, coerce={coerce}')
    print(f'  phrases={phrases}')
    if cflags:
        print(f'  context_flags={cflags}')
    if rflags:
        print(f'  risk_flags={rflags}')
    print()
