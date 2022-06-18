import PySimpleGUI as sg


def start_gui():
    # the color theme of the window
    sg.theme('DarkAmber')
    # the font of the title
    title_font = ("Ariel", 40)
    # the font f the normal text
    normal_font = ("Ariel", 20)
    # the font of the paragraphs
    long_font = ("Ariel", 15)

    # <<<<<< Stuff for the first window >>>>>> #

    # sg.text variable for the title
    vpn_name = sg.Text(
        "!coolVPNברוכים הבאים ל",
        font=title_font,
        justification="right"
    )

    # sg.text variable for the made by
    made_by = sg.Text("נכתב על ידי נוראל גליק וטל ברילנט", font=normal_font, justification="right")

    # sg.text variable for the first and second paragraph
    explanation = sg.Text(
        "מטרתו היא לחבר משתמש מרשת אחת לרשת שניה. עם השנים גילו שבעזרת הטכנולוגיה הזאת\nאפשר גם להחביא את הזהות "
        "שלך ברשת, הוא עושה זאת בכמה דרכים. הדרך הראשונה היא\nהצפנה של כל המידע שיוצא מהמשתמש לשאר העולם דרך "
        "האינטרנט, והדרך השנייה היא\nהסוואה של המחשב שלך באינטרנט\n\nהדבר הכי טוב והעיקרי הוא שאף אחד חוץ מהשרת, "
        "אפילו ספק האינטרנט שלך, לא יכולים\nלראות את המידע שהמשתמש שולח או מקבל דרך האינטרנט כמו אתרים שהמשתמש\n"
        "נכנס אליהם או דברים שהמשתמש מוריד",
        justification="right",
        font=long_font
    )

    explanation_2 = sg.Text(
        "שימוש בתוכנה הוא דבר שיתרום לכל אחד באופן כללי, ובעיקר לאנשים המעוניינים\n באבטחה גבוהה ברשת, בביטחון מידע "
        "ובפרטיות.  אבטחה ברשת נשמע מאוד טוב, אבל\n מה זה בעצם אומר? זה אומר שאי אפשר לגנוב מהמשתמש מידע, אי אפשר לדעת את"
        "\nהיסטוריית הגלישה של המשתמש ולכן אי אפשר לדוגמה לשלוח אותה למפרסמים\nועוד גופים שאף אחד לא רוצה שיחזיקו במידע "
        "שלו. "
        "אבל אבטחה ברשת אומרת\nהרבה יותר מזה, אבטחה ברשת אומרת שלהאקר שמנסה לפרוץ למכשיר\n של משתמש יהיה הרבה יותר קשה עד "
        "לכמעט בלתי אפשרי להצליח\n אם המשתמש מחזיק בתוכנה שלנו",
        justification="right",
        font=long_font
    )
    # vpn_picture = sg.Image('VPN.png', size=(300,300))

    # <<<<<< Stuff for the second window >>>>>> #

    user_guide = sg.Text("מדריך למשתמש", justification="right", font=title_font)
    first_step = sg.Text(
        "לפני שנשתמש בתוכנה ישנם כמה דברים שנצטרך לעשות קודם לכן. קודם כל, יש להתקין את הספריות\n הרלוונטיות"
        " דרך פיפ של שפת התכנות פייטון. הספריות הן ",
        justification="right",
        font=long_font
        )
    libraries = sg.Text("Threading, scapy, binascii, json, rsa, cryptography, base64, pysimplegui",
                        justification="center",
                        font=long_font
                        )
    second_step = sg.Text("לאחר מכן, יש להוסיף ממשק רשת חדש למערכת ההפעלה", justification="right",
                          font=long_font)
    third_step = sg.Text("עכשיו יש לוודא שהשרת רץ", justification="right",
                         font=long_font)
    forth_step = sg.Text("וכעת כל מה שנשאר זה להריץ את תוכנת הלקוח", justification="right",
                         font=long_font)
    more_info = sg.Text("בשביל מידע נוסף ומפורט לגבי הרצת התוכנה יש לגשת לפרק המדריך למשתמש בספר הפרויקט")

    # <<<<<< Stuff for the third window >>>>>> #

    thank_you = sg.Text("תודה רבה לכם שבחרתם להשתמש בתוכנה שלנו, אנחנו בטוחים שלא תתחרטו", justification="right",
                        font=normal_font)

    # First layout.
    layout_column1 = [[vpn_name],
                      [made_by],
                      [explanation],
                      [explanation_2]]

    layout1 = sg.Column(layout_column1, key='-COL1-', element_justification='right')

    # Second layout
    layout_column2 = [[user_guide],
                      [first_step],
                      [libraries],
                      [second_step],
                      [third_step],
                      [forth_step],
                      [more_info]]

    layout2 = sg.Column(layout_column2, visible=False, key='-COL2-', element_justification='right')

    # Third layout
    layout_column3 = [[thank_you]]

    layout3 = sg.Column(layout_column3, visible=False, key='-COL3-', element_justification='right')

    # the layout that has the first 3 layouts
    main_layout = [[layout1, layout2, layout3], [sg.Button('Next'), sg.Button('Exit')]]

    # Create the Window
    window = sg.Window('coolVPN', main_layout, size=(880, 800))
    # Event Loop to process "events" and get the "values" of the inputs

    layout = 1  # The currently visible layout

    while True:
        event, values = window.read()
        print(event, values)
        # if the Exit button has been clicked
        if event in (None, 'Exit'):
            break
        # if the Next buttone has been clicked
        if event == 'Next':
            if layout != 3:
                window[f'-COL{layout}-'].update(visible=False)
                layout = layout + 1 if layout < 3 else 1
                window[f'-COL{layout}-'].update(visible=True)
            else:
                break
    window.close()
