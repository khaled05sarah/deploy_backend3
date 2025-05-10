require('dotenv').config();
const mongoose = require('mongoose');
const Panneau = require('./models/panneau');

// 📌 Connexion à MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("✅ Connecté à MongoDB"))
    .catch(err => console.error("❌ Erreur de connexion :", err));

// 📌 Données complètes des panneaux
const panneaux = 
    [
        {
            "categorie": "arret_stop",
            "explication_generale": "تحجز أو تنظم هذه العلامات وقوف أو توقف العربات بمكان أو زمان معين\nشكلها و لونها: شكلها دائري أما لونها فهو أزرق وهي محاطة و مشطوبة باللون الأحمر",
            "exemples": [
                { "description": "ممنوع الوقوف","image":"assets/img_21.png" },
                { "description": "ممنوع الوقوف و التوقف","image":"assets/img_22.png"  },
                { "description": "ممنوع الوقوف من 1 إلى 15 من الشهر","image":"assets/img_23.png"  },
                { "description": "ممنوع الوقوف من 1 إلى 31 من الشهر","image":"assets/img_24.png"  },
                { "description": "دخول إلى منطقة يمنع فيها الوقوف","image":"assets/img_25.png"  },
                { "description": "دخول إلى منطقة يكون الوقوف فيها بالتداول كل نصف شهر من جهة ولمدة محددة" ,"image":"assets/img_26.png" },
                { "description": "دخول إلى منطقة وقوف بمقابل","image":"assets/img_27.png"  },
                { "description": "  خروج منطقة وقوف بمقابل","image":"assets/img_28.png" },
                { "description": "دخول إلى منطقة الوقوف محدد بوقت ومراقب باسطوانة" ,"image":"assets/img_29.png"},
                { "description": " خروج من منطقة الوقوف محدد بوقت ومراقب باسطوانة" ,"image":"assets/img_30.png"},
                { "description": "ممنوع الوقوف إلى غاية العلامة","image":"assets/img_31.png" },
                { "description": "ممنوع الوقوف على يسار  العلامة" ,"image":"assets/img_32.png"},
                { "description": "ممنوع الوقوف ابتداء من العلامة" ,"image":"assets/img_33.png"},
                { "description": "ممنوع الوقوف قبل و بعد العلامة" ,"image":"assets/img_34.png"}
            ]
        },
        {
            "categorie": "interdiction",
        
                "explication_generale": "هي عالمات تنظيمية تحمل تعليمات محددة لمستعملي الطريق يلتزمون بها لتجنب اختلال حركة المرور\n تعني هذه االعلامات المنع إذا كانت محاطة باللون الأحمر\nشكلها و لونها : شكلها دائري و لونها أبيض و هي محاطة باللون الأزرق الداكن أو اللون الأسود\n موضعها : توضع هذه العلامات بصفة عامة ماشرة على جانبي الرصيف أو على الحاشية الترابية قرب مكان المنع\n يبدأ مفعولها عند العلامة و ينتهي عند المفترق القادم لذلك يجب إعادة تثبيتها بعد كل تقاطع طرقات\n. عند الدخول إلى مواطن العمران, يقطع إعلام مستعملي الطريق بمنع الجولان بواسطة علامات مثبتة بعد علامة الدخول إلى مواطن العمران\n. ولا يطبق المنع إلا على الطريق الذي تم عليه تثبيت علامة المنع\n علامات نهاية المنع : يكون أيضا شكلها دائري ولونها أبيض إلا أنها مشطوبة بخط أسود",
               "exemples": [
                { "description": "ممنوع الجولان في الاتجاهين", "image": "assets/img_35.png" },
                {"description": "اتجاه ممنوع على كل العربات", "image": "assets/img_36.png" },
                { "description": "ممنوع الجولان على العربات التي يفوق وزنها على المغزل الواحد 2500 كغ", "image": "assets/img_37.png" },
                { "description": "يمنع الجولان دون ترك مسافة بين العربات لا تقل عن المسافة المبينة بالعلامة", "image": "assets/img_38.png" },
                { "description": "ممنوع استعمال المنبهات الصوتية", "image": "assets/img_39.png" },
    { "description": "ممنوع الجولان على العربات الناقلة لكمية معينة من مواد متفجرة أو سريعة الالتهاب", "image": "assets/img_40.png" },
    { "description": "ممنوع الجولان على العربات الناقلة لكمية معينة يمكنها تلويث المياه", "image": "assets/img_41.png" },
    { "description": "ممنوع الجولان على العربات الناقلة لمواد خطرة", "image": "assets/img_42.png" },
    { "description": "يمنع تجاوز السرعة المبينة بالعلامة", "image": "assets/img_43.png" },
    { "description": "نهاية منع المجاوزة بالنسبة لعربات نقل البضائع و التي يفوق وزنها الجملي المرخص 3500 كغ", "image": "assets/img_44.png" },
    { "description": "نهاية منع مجاوزة كل العربات ذات محرك باستثناء تلك التي لها عجلتين و بدون عربة جانبية", "image": "assets/img_45.png" },
    { "description": "نهاية جميع الموانع المعلنة سابقا والملزمة للعربات التي هي في حالة سير. نهاية هذه الموانع تشمل كل العربات المتحركة", "image": "assets/img_46.png" },
    { "description": "نهاية تحديد السرعة", "image": "assets/img_47.png" },
    { "description": "نهاية منع إستعمال المنبهات الصوتية", "image": "assets/img_48.png" },
    { "description": "ممنوع الدوران على اليسار في المفترق القادم", "image": "assets/img_49.png" },
    { "description": "ممنوع الدوران على اليمين في المفترق القادم", "image": "assets/img_50.png" },
    { "description": "ممنوع الجولان على الأعقاب بالطريق المتبع إلى غاية المفترق القادم", "image": "assets/img_51.png" },
    { "description": "فسح مجال المرور للعربات القادمة من الاتجاه المعاكس", "image": "assets/img_52.png" },
    { "description": "ممنوع مجاوزة كل العربات ذات محرك باستثناء العربات ذات العجلتين غير المجهزة بعربة جانبية", "image": "assets/img_53.png" },
    { "description": "ممنوع على العربات المعدة لنقل البضائع التي يفوق وزنها الجملي المرخص فيه 23500 كغ أن تتجاوز العربات ذات محرك باستثناء العربات ذات العجلتين غير المجهزة بعربة جانبية", "image": "assets/img_54.png" },
    { "description": "ممنوع المرور دون توقف (ديوانة)", "image": "assets/img_55.png" },
    { "description": "ممنوع المرور دون توقف (شرطة)", "image": "assets/img_56.png" },
    { "description": "ممنوع الجولان على العربات ذات المحرك", "image": "assets/img_57.png" },
    { "description": "ممنوع الجولان على عربات نقل البضائع", "image": "assets/img_58.png" },
    { "description": "ممنوع الجولان على المترجلين", "image": "assets/img_59.png" },
    { "description": "ممنوع مرور الدراجات", "image": "assets/img_60.png" },
    { "description": "ممنوع الجولان على العربات المجرورة بحيوان", "image": "assets/img_61.png" },
    { "description": "ممنوع الجولان على العربات المجرورة باليد", "image": "assets/img_62.png" },
    { "description": "ممنوع الجولان على العربات والمعدات الفلاحية ذات المحرك", "image": "assets/img_63.png" },
    { "description": "ممنوع المرور على الدراجات النارية الصغيرة", "image": "assets/img_64.png" },
    { "description": "ممنوع الجولان على العربات و العربات المركبة التي يفوق طولها باعتبار الحمولة الطول المبين بالعلامة", "image": "assets/img_65.png" },
    { "description": "ممنوع الجولان على العربات التي يفوق علوها باعتبار الحمولة العلو المبين بالعلامة", "image": "assets/img_66.png" },
    { "description": "ممنوع الجولان على العربات التي يفوق عرضها باعتبار الحمولة العرض المبين بالعلامة", "image": "assets/img_67.png" }

]},
        {
            "categorie": "danger",
          "explication_generale": "تهدف إشارات وعلامات الخطر إلى تنبيه مستعملي الطريق إلى الأماكن التي يجب عليهم الإنتباه بها بسبب وجود عوائق خطرة\nوتفرض عليهم تخفيضا من السرعة ملائماً لنوع الخطر المشار إليه.\n\nشكلها و لونها :\nمثلث متساوي الأضلاع، قاعدته أفقية، أما لونها أبيض وهي محاطة بخط أحمر، ويكون الرمز باللون الأسود.\n\nموضعها :\n~ خارج مواطن العمران :\nتوضع علامات الخطر قبل حوالي 150 مترا من بداية المنطقة المعنية بالخطر.\n\n~ داخل مواطن العمران :\nتوضع هذه العلامات على بعد 50 مترا أو أقل من المنطقة المعنية بالخطر.\n\nيمكن وضع هذه العلامات على مسافات أقل من المسافات المذكورة أعلاه،\nوفي هذه الحالة تبين المسافة التقريبية بين العلامة والمكان الخطير بلافتة تكميلية.",


            "exemples": [
                { "description": "منعرج على اليمين", "image": "assets/img_68.png" },
                { "description": "منعرج على اليسار", "image": "assets/img_69.png" },
                { "description": "منعرجات متتالية أولها على اليسار", "image": "assets/img_70.png" },
                { "description": "منعرجات متتالية أولها على اليمين", "image": "assets/img_71.png" },
                { "description": "طريق مسنم", "image": "assets/img_72.png" },
                { "description": "مخفض للسرعة", "image": "assets/img_73.png" },
                { "description": "طريق ضيق من اليسار", "image": "assets/img_74.png" },
                { "description": "طريق ضيق من اليمين", "image": "assets/img_75.png" },
                { "description": "طريق ضيق من الجهتين", "image": "assets/img_76.png" },
                { "description": "طريق منزلق", "image": "assets/img_77.png" },
                { "description": "جسر متحرك", "image": "assets/img_78.png" },
                { "description": "طريق تنتهي إلى رصيف أو حافة نهر", "image": "assets/img_79.png" },
                { "description": "الإعلان عن إشارة ضوئية تنظم الجولان", "image": "assets/img_80.png" },
                { "description": "خطر مجهول", "image": "assets/img_81.png" },
                { "description": "رياح جانبية", "image": "assets/img_82.png" },
                { "description": "جولان في الإتجاهين", "image": "assets/img_83.png" },
                { "description": "خطر سقوط حجارة", "image": "assets/img_84.png" },
                { "description": "منحدر خطير", "image": "assets/img_85.png" },
                { "description": "عبور منطقة بها خطر طيران", "image": "assets/img_86.png" },
                { "description": "تقاطع طريق مع سكة حديدية غير محروسة", "image": "assets/img_87.png" },
                { "description": "تقاطع طريق مع سكة حديدية محروسة", "image": "assets/img_88.png" },
                { "description": "مكان يكثر فيه الأطفال", "image": "assets/img_89.png" },
                { "description": "مفترق طرقات دوراني", "image": "assets/img_90.png" },
                { "description": "ممر للمرتجلين", "image": "assets/img_91.png" },
                { "description": "خروج دراجات", "image": "assets/img_92.png" },
                { "description": "مرور حيوانات مركوبة", "image": "assets/img_93.png" },
                { "description": "مرور حيوانات وحشية", "image": "assets/img_94.png" },
                { "description": "مرور حيوانات أهلية", "image": "assets/img_95.png" }
                
            ]
        },
        {
            "categorie":"priorite",
             "explication_generale": "تنظيم هذه العلامات السير بالمفترقات و تبين أولويات المرور لضمان سهولة حركة الجولان\nشكلها و لونها : لها أشكال متعددة لجلب انتباه مستعملي الطريق\n موضعها : توضع هذه العلامات قرب المفترقات على اليمين و يمكن أن تعاد من أعلى أو يسار المعبد\nيمكن أن تكمل علامات الأولوية بلافتة لرسم السبيل الذي يتمتع فيه السواق بأولوية المرور بالمفتقد القادم",
              "exemples": [
                { "description": "طريق ذات  أولوية. تطبق فيه الأولوية بكل المفترقات","image":"assets/img_99.png" },
                { "description": "طريق ذات  أولوية. تمثل اللافتة رسما للمفترق القادم مع الإشارة بواسطة خط سميك لفروع المفترق التي تتمتع بالأولوية","image":"assets/img_100.png" },
                { "description": "نهاية طريق ذات  أولوية","image":"assets/img_101.png" },
                { "description": "مفترق مع طريق يجب على مستعمليه ترك الأولوية. لكن لا يقع تطبيق الأولوية إلا بالمفترق القادم" ,"image":"assets/img_102.png"},
                { "description": " مفترق طرقات دوراني يكمل في أغلب الأحيان بلافتة ليس لديك الأولوية و هذه علامة متقدمة تقع الإشارة إليها على عين المكان بعلامة فسح المجال " ,"image":"assets/img_103.png"},
                { "description": "توقف عند حد المعبد الذي ستقترب منه مع فسح المجال للعربات القادمة من اليمين و اليسار. توضع هذه العلامة على عين المكان و تكمل بخط عرضي أبيض عند الإقتضاء" ,"image":"assets/img_104.png"},
                { "description":" إعلان عن علامة 'قف 'على المسافة التقريبية المبينة" ,"image":"assets/img_105.png"},


                
                
                { "description": "افسح المجال في المفترق. تكمل هذه العلامة عادة بخط عرضي متقطع ","image":"assets/img_106.png" },

                
                
               

                { "description": "تمثل هذه العلامة ركيزة مفترق تهدف إلى الإشارة إلى مكان المفترق لكنها لا تقدم معلومات عن نظام الأولوية المزمع تطبيقه","image":"assets/img_107.png" },
                
            ]
        },
        {
            "categorie": "obligation",
            
                "explication_generale": "هي علامات تنظيميه تجبر مستعملي الطريق على اتباع الاشارات التي تحملها\n,شكلها و لونها : شكلها دائري ولونها ازرق اما نوعيه الجبر فتكون باللون الأبيض\n, موضعها : توضع هذه العلامات بصوره عامه مباشره قرب المكان الذي يبدا فيه الالتزام. ويجب اعاده وضعها بعد كل تقاطع طرقات.\nغير ان بعض العلامات توضع قبل المكان الذي يطبق فيه الالتزام الذي يشير اليه وذلك على مسافه كافيه حسب وضعيه هذا المكان أما علامات نهايه الجبر فيكون شكلها دائري وتكون محاطه باللون الابيض الا انها مشطوبه باللون الاحمر",
              
              "exemples": 
              [
                { "description": "اتجاه الى اليمين اجباري في المفترق القادم" ,"image":"assets/img_108.png"},
                { "description": "اتجاه الى اليسار اجباري في المفترق القادم" ,"image":"assets/img_109.png"},
                { "description": "اتجاه الى الامام اواليمين  اجباري في المفترق القادم","image":"assets/img_110.png" },
                { "description": "اتجاه الى الامام او اليسار اجباري في المفترق القادم","image":"assets/img_111.png" },
                { "description": "اتجاه الى اليمين او اليسار اجباري في المفترق القادم" ,"image":"assets/img_112.png"},
                { "description": "اتجاه الى الامام اجباري في المفترق القادم","image":"assets/img_113.png" },
                { "description": "الدوران الى اليسار اجباري قبل العلامة","image":"assets/img_114.png" },
               { "description": "الدوران الى اليمين اجباري قبل العلامة" ,"image":"assets/img_115.png"},
               { "description": "حاجز يجب الإحاطة به من اليسار " ,"image":"assets/img_116.png"},
               { "description": "حاجز يجب الإحاطة به من اليمين" ,"image":"assets/img_117.png"},
               { "description": "مسلك او سبيل اجباري للدراجات الهوائية بدون عربة جانبيه او مجروره","image":"assets/img_118.png"}, 
               { "description": "سبيل اجباري للمترجلين","image":"assets/img_119.png" },
               { "description": "سبيل اجباري لركوب الخيل" ,"image":"assets/img_120.png"},
               { "description": "ادنى سرعه اجباريه" ,"image":"assets/img_121.png"},
              { "description": "مسلك خاص بعربات الخدمات المنتظمة للنقل الجماعي" ,"image":"assets/img_122.png"},
              { "description": "اشعال أضواء السيارة اجباري" ,"image":"assets/img_123.png"},
              { "description": "نهاية الالتزام المذكور بطبيعته." ,"image":"assets/img_124.png"},              
               { "description": "نهاية الرواق الخاص بالدراجات الهوائية" ,"image":"assets/img_125.png"},
               { "description": "نهاية الرواق الاجباري على الراجلين","image":"assets/img_126.png" },
                { "description": " نهاية الرواق الاجباري على الخيالة","image":"assets/img_127.png" },
                 { "description": "نهاية السرعة الادنى الإجبارية" ,"image":"assets/img_128.png"},
                 
                 { "description": "نهاية المسلك الاجباري للحافلات","image":"assets/img_129.png" }
            ]
        },
        {
            "categorie": "indication",
            "explication_generale":  "تهدف علامات الإرشاد إلى توجيه مستعملي الطريق وتمكينهم من الحصول على المعلومات الضرورية أثناء السياقة لتسهيل تنقلهم وضمان سلامتهم\n, شكلها ولونها : تأخذ شكلاً مستطيلاً أو مربعاً ولونها يكون أزرق مع رموز أو كتابات باللون الأبيض\n, موضعها : توضع هذه العلامات على جانب الطريق أو فوقه، حسب نوع المعلومات التي تقدمها، لضمان رؤيتها بوضوح من قبل السائقين",
            "exemples": [
                { "description": "سرعه منصوح بها","image":"assets/img_139.png" },
                { "description": "نهايه السرعه منصوح بها","image":"assets/img_140.png" },
                { "description": "حظيره السيارات" ,"image":"assets/img_141.png"},
                
                { "description": "حظيره سيارات بالدفع","image":"assets/img_142.png"}, 
                { "description": "حظيره خاصه بحافلات النقل العمومي","image":"assets/img_143.png" },
                { "description": "مستشفى" ,"image":"assets/img_144.png"},
                { "description": "طريق بدون منفذ" ,"image":"assets/img_145.png"},
                { "description": "لي اولويه السير على الاتجاه المعاكس" ,"image":"assets/img_146.png"},
                { "description": "توزيع المسالك","image":"assets/img_147.png" },
               { "description": "تخفيض المسالك" ,"image":"assets/img_148.png"},
               { "description": "ممهل","image":"assets/img_149.png" },
               { "description": "مسلك للنجده","image":"assets/img_150.png" },
              
               { "description": "التوقف مسموح على الرصيف" ,"image":"assets/img_151.png"},
               { "description": "نهايه الطريق الخاص بالسيارات","image":"assets/img_152.png" },
               { "description": "موقف سيارات الاجره","image":"assets/img_153.png" },
              
               { "description": "موقف الترامواي","image":"assets/img_154.png" },
               { "description": "طريق في اتجاه واحد","image":"assets/img_155.png" },
                         { "description": " ممر الراجلين" ,"image":"assets/img_156.png"},
                         { "description": "طريق خاص بالسيارات","image":"assets/img_157.png" },
                         
                         { "description": "مركز اسعاف" ,"image":"assets/img_158.png"},
                         { "description": "مكان للاستراحه" ,"image":"assets/img_159.png"},
                          { "description": "خاص بالمعوقين حركيا","image":"assets/img_160.png" },
                         
                          { "description": "غابه سريعه الالتهاب","image":"assets/img_161.png" },
                          { "description": "هاتف عمومي" ,"image":"assets/img_162.png"},
                          { "description": "تصليح العجلات" ,"image":"assets/img_163.png"},
                         
                          { "description": "مقهى" ,"image":"assets/img_164.png"},
                          { "description": "مطعم" ,"image":"assets/img_165.png"},
                          { "description": "محطه الوقود" ,"image":"assets/img_166.png"},
                         { "description": "هاتف النجده","image":"assets/img_167.png" },
                         { "description": "مركز استعلام سياحي","image":"assets/img_168.png"},
                         { "description": "مدخل النقق","image":"assets/img_169.png" },
                         { "description": "مخرج النقق","image":"assets/img_170.png" },
                         { "description": "بداية الطريق السيار","image":"assets/img_171.png" },
                         { "description": "نهاية الطريق السيار","image":"assets/img_172.png" }
            ]
        },
        {
            "categorie":"temp",
        
                "explication_generale": "لعلامات الوقيه مستعملي الطريق وترشدهم لوجود الحواجز او اخطار او اشغال وقتيه يمكن ان تعترضهم وذلك لحمايتهم وحمايه العاملين بها وتسحب هذه العلامات بزوال سبب وضعها\n,شكلها : تأخذ العلامات الوقتيه جميع اشكال العلامات الاخرى حسب مدلولها\n, موضعها : توضع هذه العلامات على مسافه 150 م او اقل او مباشره على عين المكان حسب نوعيه الخطر",
        
              
            "exemples": [
                { "description": " مخروط اشغال يشير الى حدود حواجز وقتيه" ,"image":"assets/img_130.png"},
                { "description": "علامه موضعيه تشير الى تغيير الاتجاه او الى تقلص عرض المعبد","image":"assets/img_131.png" },
                { "description": "اوتاد متحركة تسمح او تمنع المرور" ,"image":"assets/img_132.png"},
                { "description": "طريق مسنم ","image":"assets/img_133.png" },
                { "description": "مقذوفات حصى","image":"assets/img_134.png" },
                { "description": "طريق ضيق" ,"image":"assets/img_135.png"},
                { "description": "طريق زلق مؤقتا ","image":"assets/img_136.png" },
                { "description": "أخطار مؤقته أخرى يمكن ان تقرن العلامة بلافته تشير الى نوع الخطر","image":"assets/img_137.png" },
                { "description": "اعلان عن اشاره ضوئية مؤقته تنظم الجولان" ,"image":"assets/img_138.png"}

            
            ]
        }
    
]

Panneau.insertMany(panneaux)
    .then(() => {
        console.log("✅ Insertion réussie !");
        mongoose.connection.close();
    })
    .catch(err => {
        console.error("❌ Erreur d'insertion :", err);
        mongoose.connection.close();
    });

// 📌 Fonction pour insérer les panneaux dans MongoDB
async function insertPanneaux() {
    try {
        await Panneau.deleteMany(); // Supprime les anciens panneaux pour éviter les doublons
        await Panneau.insertMany(panneaux);
        console.log("✅ Tous les panneaux ont été insérés avec succès !");
        mongoose.connection.close();
    } catch (error) {
        console.error("❌ Erreur lors de l’insertion :", error);
    }
}

insertPanneaux();
