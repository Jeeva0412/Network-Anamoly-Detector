#!/usr/bin/env python3
"""
Flask Web Application for PCAP Analysis
Main entry point for the separate PCAP analyzer environment
"""

from flask import Flask, render_template, request, flash, redirect, url_for
import os
from werkzeug.utils import secure_filename
from pcap_processor import PCAPAnalyzer
from email_sender import SecurityAlertSender  # Use DemoAlertSender for testing

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'network-security-analyzer-2024'

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize analyzer and email sender
analyzer = PCAPAnalyzer()  # No model path for demo - uses rule-based analysis
email_sender = SecurityAlertSender()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page with upload form"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_file():
    """Handle PCAP file upload and analysis"""
    if 'file' not in request.files:
        flash('❌ No file selected', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('❌ Please select a file', 'danger')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # Secure filename and save
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Analyze the PCAP file
            analysis_result = analyzer.analyze_pcap(filepath)
            
            # Send email alert
            email_sent = email_sender.send_alert(analysis_result)
            
            # Prepare result message
            if analysis_result['is_malicious']:
                message = f"🔴 MALICIOUS TRAFFIC DETECTED! Confidence: {analysis_result['confidence']:.1%}"
                category = 'danger'
            else:
                message = f"✅ NORMAL TRAFFIC - All clear! Confidence: {analysis_result['confidence']:.1%}"
                category = 'safe'
            
            if email_sent:
                message += " 📧 Alert sent!"
            
            flash(message, category)
            
            # Add detailed analysis to flash message
            flash(f"Analysis Method: {analysis_result['analysis_method']} | Packets: {analysis_result['packet_count']}", 'info')
            
        except Exception as e:
            flash(f'❌ Analysis failed: {str(e)}', 'danger')
        
        finally:
            # Clean up uploaded file
            if os.path.exists(filepath):
                os.remove(filepath)
        
        return redirect(url_for('index'))
    
    else:
        flash('❌ Invalid file type. Please upload a .pcap or .pcapng file', 'danger')
        return redirect(url_for('index'))

@app.route('/test/<sample_type>')
def test_sample(sample_type):
    """Test with sample PCAP files"""
    sample_files = {
        'normal': 'normal_traffic.pcap',
        'suspicious': 'suspicious_traffic.pcap', 
        'malware': 'malware_traffic.pcap'
    }
    
    if sample_type in sample_files:
        filepath = sample_files[sample_type]
        if os.path.exists(filepath):
            try:
                analysis_result = analyzer.analyze_pcap(filepath)
                
                if analysis_result['is_malicious']:
                    message = f"🔴 {sample_type.upper()} SAMPLE: MALICIOUS - Confidence: {analysis_result['confidence']:.1%}"
                    category = 'danger'
                else:
                    message = f"✅ {sample_type.upper()} SAMPLE: NORMAL - Confidence: {analysis_result['confidence']:.1%}"
                    category = 'safe'
                
                flash(message, category)
                flash(f"Analysis Method: {analysis_result['analysis_method']} | Packets: {analysis_result['packet_count']}", 'info')
                
                # Send demo email
                email_sender.send_alert(analysis_result)
                
            except Exception as e:
                flash(f'❌ Sample analysis failed: {str(e)}', 'danger')
        else:
            flash('❌ Sample file not found. Run sample_pcap_generator.py first.', 'danger')
    else:
        flash('❌ Invalid sample type', 'danger')
    
    return redirect(url_for('index'))

def main():
    """Main function to run the application"""
    # Create uploads directory
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    print("🎯 Starting Network Security Analyzer...")
    print("=" * 50)
    print("📁 Separate PCAP Analyzer Environment")
    print("🌐 Web interface will be available at: http://localhost:5000")
    print("📧 Email alerts: Demo mode (prints to console)")
    print("🔍 Analysis: Rule-based detection")
    print("=" * 50)
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()