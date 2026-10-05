# CLAUDE.md — vamp-darkweb-intel

> Parte de **VampSecure Labs Security Research Division**.
> Lee también `../CLAUDE.md` (reglas VampSecureLabs) y `~/Proyectos/CLAUDE.md` (reglas globales).

## Atribución

- **Autor del código**: VampSecure Studios
- **Cabecera obligatoria** en todo fichero fuente:
  ```
  © VampSecure Studios — VampSecure Labs Security Research Division
  ```
- **Commits**: `VampSecure Studios <belky@protonmail.ch>` — sin Co-Authored-By de ningún tipo.
- **Remotos**: `github` (Vampsecure-Labs/vamp-darkweb-intel) y `forgejo` (vampsecure/vamp-darkweb-intel). Nunca `origin`.

## Código

- Comentarios y documentación en **español**.
- Sin referencias a IA como autora en comentarios, docstrings ni cabeceras.
- Secretos nunca en el repo (ver reglas globales para lista completa).
- `.env.example` es el único fichero de entorno versionable; `.env` siempre en `.gitignore`.

## Fuentes de datos

- Todas las peticiones llevan `User-Agent: VampSecure-Labs/vamp-darkweb-intel/<versión>`.
- Respetar rate limits de cada API; no añadir retries agresivos.
- Las claves API (OTX_API_KEY, HIBP_API_KEY) se leen exclusivamente de variables de entorno, nunca de argumentos CLI.
