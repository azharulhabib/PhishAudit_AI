================================================================================
  PhishAudit AI  |  Forensic URL Intelligence for the Modern Web
================================================================================

  "Not every threat announces itself. PhishAudit AI finds the ones that don't."

--------------------------------------------------------------------------------
  THE PROBLEM
--------------------------------------------------------------------------------

  Blacklists are reactive by nature. A phishing URL has to claim its first
  victims before it ever makes it onto a threat feed. By then, the damage is
  done. PhishAudit AI was built to close that window -- detecting threats that
  have never been seen before, before anyone gets hurt.

--------------------------------------------------------------------------------
  WHAT IT DOES
--------------------------------------------------------------------------------

  PhishAudit AI sits quietly inside Chrome and audits every URL before the
  page loads. Not after. Not on request. Before.

  It doesn't just check a list. It runs a forensic analysis -- dissecting the
  URL's structure, character patterns, and digital anatomy through a hybrid
  Machine Learning pipeline. The verdict comes back in milliseconds, along with
  a plain-language explanation of exactly what triggered the alert.

  When something is wrong, the user sees why. When everything is fine, they
  never know the tool was there.

--------------------------------------------------------------------------------
  WHY IT'S DIFFERENT
--------------------------------------------------------------------------------

  Most security tools answer one question: "Have we seen this before?"
  PhishAudit AI answers a harder one: "Does this look like it intends harm?"

  The hybrid engine pairs a Random Forest classifier (fast, high-confidence
  pattern matching) with a CNN/LSTM deep learning model (character-level
  sequence analysis) to catch the structural deception that Zero-Day phishing
  URLs rely on. Neither model alone is sufficient. Together, they cover the
  gaps.

  Beyond detection, the tool surfaces its reasoning. The "Deep Learning
  Insights" panel shows users and analysts exactly what the model reacted to --
  because a security tool that can't explain itself isn't one you should trust.

--------------------------------------------------------------------------------
  CORE FEATURES
--------------------------------------------------------------------------------

  Zero-Day Detection     Identifies threats with no prior blacklist record
                         using structural and behavioral URL analysis.

  Pre-Load Interception  The audit runs before the phishing page ever renders.
                         Users are protected, not warned after the fact.

  Forensic Reports       Every flagged URL comes with a risk score and a
                         human-readable breakdown of the threat signals found.

  User Control           False positives happen. Users can whitelist trusted
                         sites and report errors to improve the system.

  Admin Dashboard        A live analytics panel for security teams -- model
                         performance metrics, audit logs, and Zero-Day events.

  Privacy First          Only the URL string is ever analyzed. No page content,
                         no user data, nothing else leaves the browser.

  Fail-Safe Design       If the backend goes offline, browsing continues
                         uninterrupted. The tool steps aside; it never blocks.

--------------------------------------------------------------------------------
  TECH STACK
--------------------------------------------------------------------------------

  Chrome Extension    JavaScript (Manifest V3)
  Extension UI        React + Vite + Tailwind CSS
  Backend API         Python + FastAPI
  ML Engine           Scikit-learn (Random Forest)  +  TensorFlow/Keras (CNN/LSTM)
  Database            PostgreSQL + SQLAlchemy + Alembic
  API Protocol        RESTful / JSON

--------------------------------------------------------------------------------
  QUICK START
--------------------------------------------------------------------------------

  Backend
    cd backend && pip install -r requirements.txt
    uvicorn main:app --reload --port 8000

  Dashboard
    cd dashboard && npm install && npm run dev

  Extension
    cd extension && npm run build
    Load /extension/dist as an unpacked extension in chrome://extensions

  API docs available at http://localhost:8000/docs

================================================================================
  PhishAudit AI  --  Because Zero-Day threats don't wait for a blacklist update.
================================================================================