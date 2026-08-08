

# 3x-ui-setup

**Habilidad de Claude Code para la implementación automatizada de servidores VPN**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) ![Platform](https://img.shields.io/badge/Platform-Linux%20VPS-orange) ![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-blueviolet)

> **Versión en ruso**: [README.ru.md](README.ru.md)

## Instalación Rápida

```bash
curl -fsSL https://raw.githubusercontent.com/AndyShaman/3x-ui-skill/main/install.sh | bash
```

O manualmente:

```bash
git clone https://github.com/AndyShaman/3x-ui-skill.git
cp -r 3x-ui-skill/skill ~/.claude/skills/3x-ui-setup
rm -rf 3x-ui-skill
```

## Descripción General

Una habilidad de Claude Code que automatiza por completo la implementación de un servidor VPN en una VPS nueva. Proporciónele la IP de su servidor y la contraseña de root: se encarga de todo, desde el endurecimiento del sistema operativo hasta dos perfiles VLESS+Reality (XHTTP + TCP/Vision) entregados como un único enlace de suscripción, con la configuración del cliente Happ.

Diseñado para principiantes que desean una conexión segura y resistente a la censura sin necesidad de aprender administración de sistemas o protocolos de proxy. Optimizado para el panorama de DPI de Rusia en 2026. La habilidad guía paso a paso el proceso, verifica puntos de control críticos y le deja un servidor endurecido y una VPN lista para usar.

## Características

- 🔒 **Endurecimiento completo del servidor** — claves SSH, firewall (UFW), fail2ban (backend systemd), ajustes de kernel
- 📦 **Panel 3x-ui** — credenciales aleatorias, vinculado a loopback (acceso solo por túnel SSH)
- ⚡ **Dos inbounds VLESS+Reality** — XHTTP (mejor resistencia a DPI) + TCP/Vision+padding (iOS + respaldo)
- 🔗 **Un solo enlace de suscripción** — ambos perfiles, con actualización automática, servido vía HTTPS
- 🌐 **VLESS TLS** — ruta opcional con dominio + SSL automático vía acme.sh
- 🎭 **Página de respaldo de Nginx** — sitio de camuflaje inofensivo para la ruta TLS
- 📱 **Guía del cliente Happ** — conexión paso a paso en cualquier dispositivo
- 🇷🇺 **Optimizado para DPI de RU 2026** — huella de Firefox, padding de Vision, documentación honesta de lista blanca
- 🖥️ **Modo remoto o local** — funciona por SSH desde tu máquina o directamente en el servidor
- ✅ **Flujo de trabajo basado en puntos de control** — acceso con clave verificado antes del bloqueo de SSH
- 👻 **ICMP deshabilitado** — el servidor no responde a ping para mayor sigilo

## Flujo de Trabajo

```
VPS nueva (IP + root + contraseña)
  |
  +-- Parte 1: Endurecimiento del servidor
  |   +-- Generación de claves SSH
  |   +-- Actualización del sistema
  |   +-- Usuario no root + sudo
  |   +-- Instalar clave SSH (usuario Y root) + prueba de inicio de sesión con clave
  |   +-- Firewall UFW
  |   +-- Endurecimiento del kernel
  |   +-- Acceso directo a la configuración SSH
  |
  +-- Parte 2: Instalación de VPN
  |   +-- Instalación del panel 3x-ui (solo loopback) + BBR
  |   +-- ICMP deshabilitado
  |   +-- Dos inbounds VLESS+Reality (XHTTP 443 + TCP/Vision 8443)
  |   +-- Servidor de suscripción + certificado LE en IP
  |   +-- Configuración del cliente Happ + verificación
  |
  +-- Finalizar (ÚLTIMO, después de verificar la clave)
  |   +-- fail2ban (systemd)
  |   +-- Bloqueo de SSH (sin root, sin contraseñas)
  |
  +-- Listo: Servidor seguro + VPN funcional
```

## Contenido Incluido

| Archivo | Descripción |
|------|-------------|
| `skill/SKILL.md` | Habilidad principal — columna vertebral de orquestación |
| `skill/references/reality-inbound.md` | Escáner SNI + ambos inbounds VLESS+Reality (XHTTP + TCP/Vision) |
| `skill/references/subscription.md` | Servidor de suscripción + certificado LE en IP desnuda + túnel del panel |
| `skill/references/client-happ.md` | Instalación, importación, conexión y solución de problemas de Happ |
| `skill/references/finalize-hardening.md` | fail2ban + bloqueo SSH con puerta de verificación de clave |
| `skill/references/guide-template.md` | Archivo de guía personal + política de secretos |
| `skill/references/whitelist-and-fallbacks.md` | Expectativas de DPI de RU, escalera de respaldos, grupo SNI |
| `skill/references/local-mode.md` | Diferencias cuando Claude Code se ejecuta en la VPS |
| `skill/references/vless-tls.md` | Ruta opcional VLESS TLS (se requiere dominio) |
| `skill/references/fallback-nginx.md` | Sitio estanza inofensivo opcional para la ruta TLS |
| `install.sh` | Script de instalación en una sola línea |

## Protocolos Soportados

| Característica | VLESS Reality | VLESS TLS |
|---------|:------------:|:---------:|
| Dominio requerido | No | Sí |
| Certificado SSL | No necesario | Automático (acme.sh) |
| Dificultad | Fácil | Media |
| Página de respaldo | Integrada (sitio destino) | Opcional (Nginx) |
| Recomendado para | Principiantes | Usuarios avanzados |

## Uso

Después de la instalación, abre Claude Code y di:

- *"Configura una VPN en mi VPS"*
- *"Tengo un servidor nuevo, ayúdame a configurar VLESS"*
- *"Endurece mi servidor e instala 3x-ui"*

La habilidad se activa automáticamente cuando Claude detecta una solicitud relevante.

## Requisitos

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (CLI)
- VPS nueva (Ubuntu/Debian) con acceso root
- Acceso SSH desde tu máquina
- *(Opcional)* Nombre de dominio — solo necesario para la ruta TLS

## Solución de Problemas

| Problema | Solución |
|---------|----------|
| `Permission denied (publickey)` | Verifica los permisos de la clave SSH: `chmod 700 ~/.ssh && chmod 600 ~/.ssh/*` |
| `Host key verification failed` | Elimina la clave antigua: `ssh-keygen -R <server-ip>` |
| Panel no accesible en el navegador | Usa un túnel SSH: `ssh -L <panel_port>:127.0.0.1:<panel_port> <nickname>` (el puerto del panel se aleatoriza en la instalación) |
| Reality no se conecta | Vuelve a ejecutar el escáner SNI para encontrar un destino funcional |
| iOS se conecta pero no hay internet | Usa el perfil TCP/8443, no XHTTP (XHTTP+Reality está roto en Happ iOS) |
| Funciona en Wi-Fi, muere en datos móviles | Región en lista blanca — una VPS extranjera no puede ayudar; ver `whitelist-and-fallbacks.md` |
| Olvidé la contraseña del panel | Reiniciar en el servidor: `sudo x-ui setting -reset` |

## Contribuciones

1. Realiza un fork del repositorio
2. Crea una rama de funcionalidad (`git checkout -b feature/improvement`)
3. Realiza tus cambios
4. Envía un pull request

## Licencia

MIT — consulta [LICENSE](LICENSE) para más detalles.

## Créditos

Construido sobre la base de estos proyectos:

- [3x-ui](https://github.com/mhsanaei/3x-ui) — Panel Xray con soporte multi-protocolo
- [Xray-core](https://github.com/XTLS/Xray-core) — el motor proxy detrás de VLESS, Reality, XHTTP y Vision
- [Happ](https://github.com/Happ-proxy) — Cliente proxy multiplataforma basado en Xray-core
