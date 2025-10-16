"""
Enhanced Email Sender - Sends security alerts based on PCAP analysis
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import time

class SecurityAlertSender:
    def __init__(self):
        self.smtp_config = {
            'server': "smtp.gmail.com",
            'port': 587,
            'sender_email': "youremail@gmail.com",
            'sender_password': "xxxx xxxx xxxx xxxx",  # Your app password "https://myaccount.google.com/apppasswords"
            'receiver_email': "receiveremail@gmail.com"
        }
        self.max_retries = 3
        self.timeout = 10
    
    def send_alert(self, analysis_result):
        """Send security alert email based on analysis results"""
        
        print(f"📧 Attempting to send email alert to {self.smtp_config['receiver_email']}...")
        
        # Create email message
        message = MIMEMultipart()
        
        if analysis_result['is_malicious']:
            message["Subject"] = "🚨 SECURITY ALERT - Malicious Network Activity Detected"
            email_body = self._create_malicious_alert_body(analysis_result)
        else:
            message["Subject"] = "✅ Security Scan Complete - All Clear"
            email_body = self._create_normal_alert_body(analysis_result)
        
        message["From"] = self.smtp_config['sender_email']
        message["To"] = self.smtp_config['receiver_email']
        
        message.attach(MIMEText(email_body, "plain"))
        
        # Try sending with retries
        for attempt in range(self.max_retries):
            try:
                print(f"📧 Email attempt {attempt + 1}/{self.max_retries}...")
                
                # Send email
                server = smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port'], timeout=self.timeout)
                server.starttls()
                server.login(self.smtp_config['sender_email'], self.smtp_config['sender_password'])
                server.send_message(message)
                server.quit()
                
                print("✅ Security alert email sent successfully!")
                return True
                
            except smtplib.SMTPAuthenticationError as e:
                print(f"❌ SMTP Authentication Failed: {e}")
                print("💡 Please check your email and app password")
                break
            except smtplib.SMTPException as e:
                print(f"❌ SMTP Error (attempt {attempt + 1}): {e}")
            except Exception as e:
                print(f"❌ Unexpected error (attempt {attempt + 1}): {e}")
            
            # Wait before retry
            if attempt < self.max_retries - 1:
                print(f"⏳ Retrying in 5 seconds...")
                time.sleep(5)
        
        print("❌ All email sending attempts failed")
        return False
    
    def test_connection(self):
        """Test SMTP connection and authentication"""
        try:
            print("🧪 Testing email configuration...")
            server = smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port'], timeout=self.timeout)
            server.starttls()
            server.login(self.smtp_config['sender_email'], self.smtp_config['sender_password'])
            server.quit()
            print("✅ Email configuration test successful!")
            return True
        except Exception as e:
            print(f"❌ Email configuration test failed: {e}")
            return False
    
    def _create_malicious_alert_body(self, result):
        return f"""
🚨 NETWORK SECURITY ALERT - IMMEDIATE ATTENTION REQUIRED

THREAT DETECTED IN CAPTURED NETWORK TRAFFIC

📊 ANALYSIS SUMMARY:
• File Analyzed: {result.get('file_path', 'Unknown')}
• Threat Level: 🔴 MALICIOUS
• Detection Confidence: {result.get('confidence', 0):.1%}
• Analysis Method: {result.get('analysis_method', 'Unknown')}
• Packet Count: {result.get('packet_count', 0)}

🔍 DETAILED FINDINGS:
{result.get('details', 'No details available')}

🚀 RECOMMENDED ACTIONS:
1. Isolate affected systems from network
2. Review firewall and IDS logs immediately
3. Scan for malware on potentially compromised devices
4. Check for unauthorized access attempts
5. Review recent system and application logs

📞 CONTACT SECURITY TEAM:
If you need immediate assistance, contact your security team.

Stay vigilant,
- Automated Network Security Monitoring System
"""
    
    def _create_normal_alert_body(self, result):
        return f"""
✅ NETWORK SECURITY SCAN COMPLETE - ALL CLEAR

SECURITY STATUS: NORMAL - NO THREATS DETECTED

📊 ANALYSIS SUMMARY:
• File Analyzed: {result.get('file_path', 'Unknown')}
• Threat Level: ✅ NORMAL  
• Confidence Level: {result.get('confidence', 0):.1%}
• Analysis Method: {result.get('analysis_method', 'Unknown')}
• Packet Count: {result.get('packet_count', 0)}

🔍 DETAILED FINDINGS:
{result.get('details', 'No details available')}

🎯 SECURITY STATUS:
All analyzed network traffic appears normal and follows expected patterns.
No signs of malicious activity were detected in the captured traffic.

📝 RECOMMENDATION:
No immediate action required. Continue regular security monitoring.

Best regards,
- Automated Network Security Monitoring System
"""

# Demo version for testing
class DemoAlertSender:
    def send_alert(self, analysis_result):
        print("📧 DEMO MODE: Email alert would be sent here")
        print(f"   To: admin@yourcompany.com")
        print(f"   Subject: {'🚨 SECURITY ALERT' if analysis_result['is_malicious'] else '✅ Security Scan Complete'}")
        print(f"   Body preview: {analysis_result.get('details', '')[:100]}...")
        return True