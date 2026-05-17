---
title: "UnCrackable Level 1 — Write-up"
date: 2026-05-17
categories: [Chall, Android]
tags: [frida, reverse, Android]
---

**بسم الله الرحمن الرحيم**


## Introduction

On se retrouve pour le premier challenge de la série Uncrackable de l'Owasp.

> **Consigne :** _A secret string is hidden somewhere in this app. Find a way to extract it._

![ecranhome](/assets/uncrackable1/ecranhome.png)

Pour valider le chall, on doit donc trouver la secret string. Allez c'est parti, on sort JADX et on commence l'analyse.

## Analyse statique 

### Manifest.xml

Premier chose à faire : Lire `AndroidManifest.xml`. Pour rappel, c'est un peu la carte d'identité de l'app et nous donne pas mal d'infos sur l'appli. 

**Ce qu'on retient :**
- **Package** : `owasp.mstg.uncrackable1` - identifiant de l'appli
- **SDK** : L'app supporte à partir d'Android 4.4 , ciblée pour Android 9
- **`allowBackup="true"`** : Mauvaise 
- Une seule Activity donc un seul écran :**sg.vantagepoint.uncrackable1.MainActivity**
- **`action.MAIN` + `category.LAUNCHER`** — c'est ce couple qui dit à Android _"affiche cette app sur l'écran d'accueil et démarre par MainActivity"_. Le point d'entrée officiel.
- **Aucune `<uses-permission>`** — pas d'accès réseau, pas de caméra, walou! Le secret est **100% local** dans l'app. Bonne nouvelle pour nous.

### Logique de l'appli 

On ouvre `MainActivity` dans JADX. On va analyser les différentes méthodes ! 

#### `m5a()`

On a une méthode **`private`** (accessible uniquement depuis l'intérieur de la classe) . Elle prend une `String` en paramètre (le titre du dialogue) et affiche une boîte de dialogue avec un message : _"This is unacceptable. The app is now going to exit."_

Le bouton OK appelle `System.exit(0)` et kill le process et `setCancelable(false)` empêche de la fermer autrement. 

On verra par la suite son utilité ! 

#### `onCreate()`

```java
protected void onCreate(Bundle bundle) {
    if (C0002c.m2a() || C0002c.m3b() || C0002c.m4c()) {
        m5a("Root detected!");
    }
    if (C0001b.m1a(getApplicationContext())) {
        m5a("App is debuggable!");
    }
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
}
```

`onCreate()` est le point d'entrée de l'Activity, Android l'appelle automatiquement au lancement. Et là, avant même d'afficher l'interface, l'app fait deux vérifications :

**Bloc 1 : Anti-root :**

```java
if (C0002c.m2a() || C0002c.m3b() || C0002c.m4c())
```

Trois fonctions de détection de root qu'on reconnait au commentaire . Si au moins une retourne `true` → `m5a("Root detected!")` et appelle justement m5a qui kill le process comme on l'a vu avant.

**Bloc 2 — Anti-debug :**

```java
if (C0001b.m1a(getApplicationContext()))
```

Il y'a également une protection anti-debug comme on peut le voir dans le commentaire . Comme l'anti-root, si un débogueur est attaché appelle  m5a qui kill le process. 

On verra après avoir expliqué ces différentes de détection, pourquoi nous avons pas eu ce message au lancement de l'app ! 

#### Méthode verify() 

`verify()` est une méthode public,  elle est appelée depuis le layout XML quand on appuie sur le bouton. Elle prend un paramètre `View` (la vue qui a déclenché l'événement, obligatoire pour les `onClick` XML).

Le fonctionnement est simple :
1. Récupère le texte saisi dans l'`EditText`
2. Le passe à `C0005a.m6a()` qui retourne `true` ou `false`
3. Affiche "Success!" ou "Nope..." selon la réponse

On sait maintenant la classe qui valide le secret ! 

#### Classe :`C0005a`

##### `m6a()` La vérification

```java
public static boolean m6a(String str) {
    byte[] bArrM0a;
    byte[] bArr = new byte[0];
    try {
        bArrM0a = C0000a.m0a(
            m7b("8d127684cbc37c17616d806cf50473cc"),
            Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0)
        );
    } catch (Exception e) {
        Log.d("CodeCheck", "AES error:" + e.getMessage());
        bArrM0a = bArr;
    }
    return str.equals(new String(bArrM0a));
}
```
On comprend vite que cette fonction prend une string (l'input), la passe par une méthode qui retourne des bytes avec 2 paramètres hardcodés dont 1 en base64, puis la compare en la transformant avec l'input pour renvoyer `true` ou `false`.

Donc maintenant qu'on a ça, on comprend que la secret string est calculée au runtime puis comparée, donc on a juste à hooker la méthode `sg.vantagepoint.a.a.a()` qui renvoie le secret en bytes mais allons le plus loin possible.

#### Classe : C0000a

##### m0a() - Déchiffrement de la secret string

```java
public static byte[] m0a(byte[] bArr, byte[] bArr2) {
    SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
    return cipher.doFinal(bArr2);
}
```


Donc il crée la `SecretKeySpec` avec le premier tableau, on comprend que c'est la clé, puis il indique l'algorithme à utiliser, on crée l'instance du `Cipher` en mode déchiffrement, et la fonction retourne `bArr2` déchiffré.

Donc on confirme que `bArr2` est le secret chiffré en base64 et bArr la clé ! Tout cela permet de comprendre qu'il est possible d'avoir le secret avec simple script qui reprend cela ! 

##### `m7b()`

Ok, on a deux manières de faire, mais avant cela regardons la dernière méthode.

```java
public static byte[] m7b(String str) {
    int length = str.length();
    byte[] bArr = new byte[length / 2];
    for (int i = 0; i < length; i += 2) {
        bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4)
                              + Character.digit(str.charAt(i + 1), 16));
    }
    return bArr;
}
```

C'est le genre de fonction que je donne à l'IA mdrr, mais on va faire les choses bien jusqu'au bout.

On a une méthode qui prend une string, elle crée une variable avec la taille de la string puis crée un tableau de bytes de taille : `longueur / 2` — logique car 2 caractères hex = 1 byte. On a une boucle qui récupère le caractère à la position `i`, le convertit de hex en entier, puis décale tous ses bits de 4 positions vers la gauche pour le placer en nibble de poids fort (nibble=4bits), puis on récupère le caractère suivant, on le convertit également et on additionne les deux pour obtenir le byte complet. On avance ensuite de deux caractères et on recommence jusqu'à la fin de la string. On force le cast en `byte` puis on stocke le résultat à l'index `i/2` pour le placer à la bonne position. Enfin on retourne le tableau. On a 32 caractères hex donc 16 bytes, ce qui correspond à une clé **AES-128**.

## Résolution 

Place à la résolution avec les 2 manières différentes ! 

### A la mano

Petit récap : On a la clé en hex qu'on convertit en bytes, on a l'algo AES-ECB, puis on a le secret chiffré et encodé en base64. On décode le base64, on déchiffre, on retire le padding et on affiche ! Je cook tout cela ! 

Commande 1, COMMANDE 1 SVPPP  :

```python

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import  base64

key = bytes.fromhex("8d127684cbc37c17616d806cf50473cc") 
secret = base64.b64decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=") 
cipher = AES.new(key, AES.MODE_ECB) 
decrypt= unpad(cipher.decrypt(secret),AES.block_size)
print(decrypt.decode())

```

### On arrive en FORCEEE !!

Deuxième manière de faire ! Vu qu'on est les rois du hook, on va hooker la méthode qui calcule le secret, intercepter ce qu'elle renvoie puis simplement la transformer en string !

Commande 2, COMMANDE 2 SVPPPP :

```
Java.perform(function () {
    var class= Java.use("sg.vantagepoint.a.a");
    class.a.implementation = function (key, data) {
        var decrypted = this.a(key, data);
        var secret = Java.use("java.lang.String").$new(decrypted);
        console.log("Secret : " + secret);
        return decrypted;
    };
});

```

![resultfrida](/assets/uncrackable1/fridaresult.png)


**Secret : I want to believe**

###  Bonus : Les classes de détection

#### Anti-root - C0002c

Trois méthodes, trois techniques de détection différentes. Ces méthodes seront expliquées en détails dans mon article "Methode de Détection root" où je recense toutes les méthodes anti-root que j'ai recontré sur mon chemin ان شاء الله. 

**Méthode 1 : Recherche du binaire su dans le PATH :**

```java
public static boolean m2a() {
    for (String str : System.getenv("PATH").split(":")) {
        if (new File(str, "su").exists()) {
            return true;
        }
    }
    return false;
}
```

Elle parcourt tous les dossiers du `PATH` système et cherche le binaire su 

**Méthode 2 : Vérification des build tags**

```java
public static boolean m3b() {
    String str = Build.TAGS;
    return str != null && str.contains("test-keys");
}
```

Elle cherche dans Build.TAGS si il y'a bien "release-keys"

**Méthode 3 : Black list des fichiers** 

```java
public static boolean m4c() {
    for (String str : new String[]{
        "/system/app/Superuser.apk",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/bin/.ext/.su",
        "/system/etc/.has_su_daemon",
        "/system/etc/.installed_su_daemon",
        "/dev/com.koushikdutta.superuser.daemon/"
    }) {
        if (new File(str).exists()) {
            return true;
        }
    }
    return false;
}
```

Elle cherche unne liste de fichiers caractéristiques des outils de root connus.

#### Anti-debug — `C0001b`

**Méthode 1 : Récupération du FLAG_DEBUGGABLE**

```java
public static boolean m1a(Context context) {
    return (context.getApplicationContext().getApplicationInfo().flags & 2) != 0;
}
```

#### Pourquoi ça n'a pas marché ?

Très bonne question ! Ici j'ai ouvert l'appli dans un émulateur donc :

- Pas de binaire su car il tourne en root directement sans passer par su

- Les images google_apis récentes signent avec "dev-key", regardons ensemble : 
![dev signing](/assets/uncrackable1/devsigning.png)


-  Les fichiers énumérés par l'appli sont souvent lié à Magisk/SuperSU (ces outils permettent de rooter un device physique)

En réalité, ces protections auraient fonctionné sur un device physique mais facilement détournable en modifiant les retour de fonction via frida.


الحمد لله

