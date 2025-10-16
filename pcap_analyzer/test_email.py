from email_sender import SecurityAlertSender

def test_email_system():
    print("🧪 Testing Email System...")
    
    # Create sender instance
    sender = SecurityAlertSender()
    
    # Test connection
    if sender.test_connection():
        print("✅ SMTP Connection Successful!")
        
        # Test sending an email
        test_result = {
            'is_malicious': True,
            'file_path': 'test.pcap',
            'confidence': 0.95,
            'analysis_method': 'Rule-Based',
            'packet_count': 150,
            'details': 'Test detection: Multiple port scans and suspicious payload patterns detected.'
        }
        
        print("📧 Sending test email...")
        success = sender.send_alert(test_result)
        
        if success:
            print("🎉 Email system is working correctly!")
        else:
            print("❌ Email sending failed. Check the error messages above.")
    else:
        print("❌ Cannot connect to email server. Please check your configuration.")

if __name__ == "__main__":
    test_email_system()