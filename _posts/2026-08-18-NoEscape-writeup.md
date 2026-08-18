---
title: "NoEscape - Write-up"
date: 2026-08-18
categories: [Chall, IOS]
tags: [IOS, reverse, anti-jailbreak]
---

**بسم الله الرحمن الرحيم**

# Introduction


AsalamAleikom la team ! Ça fait longtemps que je n'ai pas publié d'article. En ce moment, j'ai focus mon apprentissage sur iOS, car je me suis aperçu que le code y est beaucoup plus lisible,  les quelques apps que j'ai reverse étaient bien bien obfusquées sur Android.

J'espère publier bientôt mon article sur le parsing de Mach-O, inchaAllah. (J'ai un tas d'articles en attente)

J'espère publier mon article sur le parsing de Mach-O bientôt inchaAllah. 

D'ailleurs, je suis aussi tombé amoureux de tout ce qui touche à la protection d'applications — jailbreak detection, RASP, etc. Mes articles vont sûrement tourner autour de ça.

Bref… C'est un peu lié à ce que je viens de citer, mais aujourd'hui on part sur un petit challenge anti-jailbreak « No Escape » de Mobile Hacking Lab. 

Ce qui est cool, c'est que c'est un des rares challs anti-jailbreak qui fonctionne sur mon device (rappel : device sous palera1n en rootless) . 

> Spoil : Bon au final , je me suis un peu emballé pour rien mdrrr

# Analyse statique

C'est parti ! Le chall est assez simple, donc je ne me suis pas pris la tête à analyser l'IPA : on ouvre directement le Mach-O sur IDA. Il n'y a pas beaucoup de fonctions, donc c'est cool.

La première chose qui me saute aux yeux, c'est la fonction `isJailBroken()` qui renvoie un booléen.

![Code_no_espace]!(/assets/img/Chall/Code_no_escape.png)

On voit qu'elle passe par 4 fonctions assez claires. On va les analyser une par une : ça va nous permettre de comprendre les différentes méthodes utilisées pour détecter le jailbreak.

Mais en réalité, il suffisait de forcer la fonction à renvoyer `0` avec Frida (ce qui signifie que l'appareil n'est _pas_ jailbreaké) pour récupérer le flag.

On ne va quand même pas passer à côté de l'aspect pédagogique et puis autant en profiter pour rassembler toutes les méthodes anti-jailbreak utilisées par les apps.

# CheckForJailBreakFiles

La première fonction est une méthode classique que j'ai vu passé dans un sdk d'une grosse app donc toujours d'actualité qui consiste à chercher des fichiers exclusivement présents sur un appareil jailbreaké pour le détecter.

On réunit les différents chemins testés :
```txt
/Applications/Cydia.app
/Library/MobileSubstrate/MobileSubstrate.dylib
/bin/bash
/usr/sbin/sshd
/etc/apt
/bin
```

Le tableau de chemins est construit, puis la fonction itère dessus et appelle `fileExistsAtPath:` sur chacun via `NSFileManager.defaultManager`. 

Dès qu'un fichier existe, elle renvoie `1`.

Ces chemins ne sont pas terribles dans mon cas, seul le  `/bin` est détecté. On va voir ça avec un petit script Frida : 

```js
/ Offset fonction à hooker
const offset=0x00A118;

// Nom Module à hooker
const Name_module="No Escape";

// Calcul base + offset
var Get_Module=Process.getModuleByName(Name_module);
var Base_Module=Get_Module.base;
var final_address=Base_Module.add(offset);

// Affichage hex pour verif
console.log(hexdump(final_address,{length:64}));

//Interceptor
Interceptor.attach(final_address,{
  onEnter: function(args){
    console.log("Fonction appelé");
    console.log("arg0:"+args[0]);
    console.log("arg1:"+args[1]);
  },
  onLeave: function(retval){ 
    console.log('Retour de la fonction'+retval)
  }
});
```

On voit que la fonction renvoie `1`. Et quand je force le retour à `0`, je bypass le chall mdrrr. Elle détectait donc uniquement grâce à `/bin`.

Ce chall n'est d'ailleurs pas très adapté aux jailbreaks modernes type palera1n (rootless), où l'on aurait plutôt cherché quelque chose comme `/var/jb`.

# CheckSandboxViolation

Au début j'étais impressionné par le nom de la fonction mdrrr, mais c'est juste un simple `fileExistsAtPath:` de plus sur : `/private/var/lib/apt/`. 

C'est le dossier de travail d'APT, le gestionnaire de paquets utilisé par Cydia.

# CanOpenCydia 

Cette fonction vérifie si un schéma d'URL `cydia://` est enregistré. On demande donc à `UIApplication` s'il peut ouvrir cette URL. Depuis iOS 9, `canOpenURL:` ne fonctionne que si le schéma interrogé est déclaré dans la clé `LSApplicationQueriesSchemes` de l'`Info.plist`. Donc il renvoie toujours `false` car il n'est pas déclaré dans l'`Info.plist` mdrrrr (on ne juge pas le chall svp mdrrr).

# Sandox Escape

Cette fonction est assez cool car elle essaye d'écrire un fichier en dehors du conteneur de l'app. 

Une app sandboxée ne peut écrire que dans son propre conteneur, à l'inverse d'un appareil jailbreaké où la sandbox est contournée.

Bon... Ici aussi mdrrrr ça marche pas, car je suis en jailbreak rootless et le volume `/` reste en read-only et tout le jailbreak vit sous `/var/jb`, donc l'écriture dans `/private/` échoue.

# Solution

Bon, on a compris que ce chall est plus adapté à un jailbreak rootful avec Cydia, mais la solution reste simple : forcer la fonction `isJailBroken()` à `0`.

```js
// Offset fonction à hooker
const offset=0x00A068;

// Nom Module à hooker
const Name_module="No Escape";

// Calcul base + offset
var Get_Module=Process.getModuleByName(Name_module);
var Base_Module=Get_Module.base;
var final_address=Base_Module.add(offset);

// Affichage hex pour verif
console.log(hexdump(final_address,{length:64}));

//Interceptor
Interceptor.attach(final_address,{
  onEnter: function(args){
    console.log("Fonction appelé");
    console.log("arg0:"+args[0]);
    console.log("arg1:"+args[1]);
  },
  onLeave: function(retval){
    retval.replace(ptr(0X0))
    console.log('Retour de la fonction'+retval)
  }
});

```

الحمد لله
