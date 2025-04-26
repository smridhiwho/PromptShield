# PromptShield
## Prompt Injection Detection System
A security tool for analyzing and detecting potential prompt injection attacks against AI systems using Google's Gemini and Streamlit.

## Overview
This application provides real-time analysis of user prompts to identify potential security threats, including:

* Attempts to override system instructions
* Exfiltration of prompt content
* Jailbreaking techniques
* Delimiter manipulation
* Multi-stage attacks
* Unicode obfuscation

The system achieves 91% accuracy in detecting malicious prompts through advanced prompt engineering with Gemini, without requiring custom model fine-tuning.

## Features

* Real-time prompt analysis: Submit text through an intuitive interface for immediate security assessment
* Detailed threat analysis: Get confidence scores, reasoning, and specific flagged patterns for each prompt
* Historical tracking: Store and review all analyzed prompts with timestamps and results
* Analytics dashboard: Monitor detection rates and trends with interactive visualizations
* Exportable data: Download analysis history for further investigation
* Lightweight persistence: Store results in SQLite database for easy deployment


## Installation

Clone this repository

```
git clone https://github.com/yourusername/prompt-injection-detection.git
cd prompt-injection-detection
```

Install dependencies
```
pip install -r requirements.txt
```

Set up your Gemini API key

Create a .env file with your API key. 

Run the application

```
streamlit run app.py
```

## Requirements

streamlit>=1.30.0
pandas>=2.0.0
google-generativeai>=0.3.0
plotly>=5.15.0

## Usage
### Analyzing Prompts

1. Navigate to the "Analysis Tool" page
2. Enter the prompt text you want to analyze in the text area
3. Click "Analyze Prompt"
4. Review the results:

Green box indicates safe prompt
Red box with warning indicates malicious prompt
Detailed reasoning and confidence score are provided



### Reviewing History

Navigate to the "History" page
Filter results by:

* Malicious prompts only
* Confidence threshold


Export data as CSV if needed

### Viewing Statistics

Navigate to the "Statistics" page
Review visual metrics:

1. Total prompts analyzed
2. Malicious prompts detected
3. Detection rate percentage
4. Daily analysis trends
5. Confidence score distributions



## How It Works
The system uses a carefully engineered prompt for Google's Gemini model to analyze submitted text for potential security threats. This approach includes:

* Input Processing: The submitted prompt is sent to Gemini with specialized security instructions
* Pattern Detection: Gemini analyzes linguistic patterns and context to identify manipulation attempts
* Risk Assessment: The system calculates a confidence score and provides detailed reasoning
* Storage: All results are saved to SQLite for historical analysis and monitoring

## Customization
You can modify the system for your needs:

- Adjust the prompt engineering in the analyze_prompt_with_gemini function
- Extend the database schema to store additional metadata
- Add new visualization types to the statistics page
- Implement additional filtering options for the history page

Keep your LLMs safe! 