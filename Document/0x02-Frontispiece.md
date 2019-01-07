# Frontispiece

## About the OWASP Mobile Security Testing Guide

The OWASP Mobile Security Testing Guide (以下、「MSTG」という。)はモバイルアプリのセキュリティ検証を行うための包括的なマニュアルです。[OWASP Mobile Application Verification Standard (以下、「MASVS」という。)](https://github.com/OWASP/owasp-masvs "MASVS")に記載されているコントロールを検証するための技術的プロセスについて説明し、一貫したセキュリティ検証のためのベースラインを用意しています。

OWASPは数多くのAuthor、レビュワー、編集者がこのガイドの開発に並々ならぬ力を注いで頂いたことに深く感謝申し上げます。本ガイドに関するご意見やご提案がありましたら、MASVSとMSTGに関するディスカッションのために、[OWASP Mobile Security ProjectのSlack Channel](https://owasp.slack.com/messages/project-mobile_omtg/details/ "OWASP Mobile Security Project Slack Channel")にご参加ください。[こちら](https://join.slack.com/t/owasp/shared_invite/enQtNDI5MzgxMDQ2MTAwLTEyNzIzYWQ2NDZiMGIwNmJhYzYxZDJiNTM0ZmZiZmJlY2EwZmMwYjAyNmJjNzQxNzMyMWY4OTk3ZTQ0MzFhMDY "Slack channel sign up")からSlack Channelに登録可能です。(inviteの有効期限が切れている場合はお知らせください)

## Copyright and License

![license](Images/license.jpg)
Copyright © 2018 The OWASP Foundation. This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). For any reuse or distribution, you must make clear to others the license terms of this work.

## Acknowledgements

**Note**: 以下のcontributor tableは、[GitHub contribution statistics](https://github.com/OWASP/owasp-mstg/graphs/contributors "GitHub contribution statistics")に基づき生成されています。詳細につきましては、[GitHub Repository README](https://github.com/OWASP/owasp-mstg/blob/master/README.md "GitHub Repository README")をご覧ください。一覧は手動更新となっているため、すぐにはリストに登録されないこともあるかと思いますが、しばらくお待ち頂ければ幸いです。

### Authors

#### Bernhard Mueller

Bernhard is a cyber security specialist with a talent for hacking systems of all kinds. During more than a decade in the industry, he has published many zero-day exploits for software such as MS SQL Server, Adobe Flash Player, IBM Director, Cisco VOIP, and ModSecurity. If you can name it, he has probably broken it at least once. BlackHat USA commended his pioneering work in mobile security with a Pwnie Award for Best Research.

#### Sven Schleier

Sven is an experienced web and mobile penetration tester and assessed everything from historic Flash applications to progressive mobile apps. He is also a security engineer that supported many projects end-to-end during the SDLC to "build security in". He was speaking at local and international meetups and conferences and is conducting hands-on workshops about web application and mobile app security.

#### Jeroen Willemsen

Jeroen is a principal security architect at Xebia with a passion for mobile security and risk management. He has supported companies as a security coach, a security engineer and as a full-stack developer, which makes him a jack of all trades. He loves explaining technical subjects: from security issues to programming challenges.

### Co-Authors

Co-authors have consistently contributed quality content and have at least 2,000 additions logged in the GitHub repository.

#### Romuald Szkudlarek

Romuald is a passionate cyber security & privacy professional with over 15 years of experience in the web, mobile, IoT and cloud domains. During his career, he has been dedicating his spare time to a variety of projects with the goal of advancing the sectors of software and security. He is teaching regularly at various institutions. He holds CISSP, CCSP, CSSLP, and CEH credentials.

### Top Contributors

Top contributors have consistently contributed quality content and have at least 500 additions logged in the GitHub repository.

- Pawel Rzepa
- Francesco Stillavato
- Henry Hoggard
- Andreas Happe
- Kyle Benac
- Alexander Anthuk
- Wen Bin Kong
- Abdessamad Temmar
- Bolot Kerimbaev
- Cláudio André
- Slawomir Kosowski

### Contributors

Contributors have contributed quality content and have at least 50 additions logged in the GitHub repository.

Jin Kung Ong, Sjoerd Langkemper,
Gerhard Wagner, Michael Helwig, Pece Milosev, Ryan Teoh, Denis Pilipchuk, Jeroen Beckers, Dharshin De Silva, Anatoly Rosencrantz, Abhinav Sejpal, Daniel Ramirez Martin, Enrico Verzegnassi, Yogesh Sharma, Dominique Righetto, Raul Siles, Nick Epson, Prathan Phongthiproek, Tom Welch, Luander Ribeiro, Dario Incalza, Akanksha Bana, Oguzhan Topgul, Carlos Holguera, Vikas Gupta, David Fern, Pishu Mahtani, Anuruddha E.

### Reviewers

Reviewers have consistently provided useful feedback through GitHub issues and pull request comments.

- Sjoerd Langkemper
- Anant Shrivastava

### Editors

- Heaven Hodges
- Caitlin Andrews
- Nick Epson
- Anita Diamond
- Anna Szkudlarek

### Others

Many other contributors have committed small amounts of content, such as a single word or sentence (less than 50 additions). The full list of contributors is available on [GitHub](https://github.com/OWASP/owasp-mstg/graphs/contributors "contributors").

### Sponsors

While both the MASVS and the MSTG are created and maintained by the community on a voluntary basis, sometimes a little bit of outside help is required. We therefore thank our sponsors for providing the funds to be able to hire technical editors. Note that their sponsorship does not influence the content of the MASVS or MSTG in any way. The sponsorship packages are described on the [OWASP Project Wiki](https://www.owasp.org/index.php/OWASP_Mobile_Security_Testing_Guide#tab=Sponsorship_Packages "OWASP Mobile Security Testing Guide Sponsorship Packages").

#### Honourable Benefactor

[![NowSecure](Images/Sponsors/NowSecure_logo.png)](https://www.nowsecure.com/ "NowSecure")


### Older Versions

The Mobile Security Testing Guide was initiated by Milan Singh Thakur in 2015. The original document was hosted on Google Drive. Guide development was moved to GitHub in October 2016.

**OWASP MSTG "Beta 2" (Google Doc)**

| Authors | Reviewers | Top Contributors |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Blessen Thomas, Dennis Titze, Davide Cioccia, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Mirza Ali, Rahil Parikh, Anant Shrivastava, Stephen Corbiaux, Ryan Dewhurst, Anto Joseph, Bao Lee, Shiv Patel, Nutan Kumar Panda, Julian Schütte, Stephanie Vanroelen, Bernard Wagner, Gerhard Wagner, Javier Dominguez | Andrew Muller, Jonathan Carter, Stephanie Vanroelen, Milan Singh Thakur  | Jim Manico, Paco Hope, Pragati Singh, Yair Amit, Amin Lalji, OWASP Mobile Team|

**OWASP MSTG "Beta 1" (Google Doc)**

| Authors | Reviewers | Top Contributors |
| --- | --- | --- |
| Milan Singh Thakur, Abhinav Sejpal, Pragati Singh, Mohammad Hamed Dadpour, David Fern, Mirza Ali, Rahil Parikh | Andrew Muller, Jonathan Carter | Jim Manico, Paco Hope, Yair Amit, Amin Lalji, OWASP Mobile Team  |
