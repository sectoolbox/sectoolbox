  Step 1: Edit backend/Dockerfile

  Add tool to the apt-get install line:

  RUN apt-get update && apt-get install -y \
      python3 \
      tshark \
      YOUR_NEW_TOOL \    ← Add here
      && rm -rf /var/lib/apt/lists/*

  Step 2: Push to GitHub

  git add backend/Dockerfile
  git commit -m "Add YOUR_TOOL to backend"
  git push

  Railway auto-deploys → tool is installed

  ---
  Examples:
  - Want nmap? → Add nmap
  - Want ffmpeg? → Add ffmpeg
  - Want binwalk? → Add binwalk
  - Want foremost? → Add foremost

Railway uses the Dockerfile, so just add to apt-get install line.

```
Dockerfile         ← Railway uses THIS
requirements.txt   ← Python packages
package.json       ← Node.js config
src/               ← Source code

```