#!/usr/bin/env python3
"""
CerberusMesh Setup Script - Interactive setup for the honeypot platform.
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def print_banner():
    """Print CerberusMesh banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗███████╗   ║
    ║  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝   ║
    ║  ██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║███████╗   ║
    ║  ██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║   ║
    ║  ╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝███████║   ║
    ║   ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ║
    ║                                                               ║
    ║                    Advanced Honeypot Platform                ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_prerequisites():
    """Check if required tools are installed."""
    required_tools = {
        'python': 'python --version',
        'docker': 'docker --version',
        'docker-compose': 'docker-compose --version',
        'terraform': 'terraform --version',
        'aws': 'aws --version'
    }
    
    missing_tools = []
    
    print("🔍 Checking prerequisites...")
    
    for tool, command in required_tools.items():
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True)
            if result.returncode == 0:
                print(f"  ✅ {tool}: Found")
            else:
                print(f"  ❌ {tool}: Not found")
                missing_tools.append(tool)
        except FileNotFoundError:
            print(f"  ❌ {tool}: Not found")
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"\n❌ Missing required tools: {', '.join(missing_tools)}")
        print("Please install them before continuing.")
        return False
    
    print("✅ All prerequisites satisfied!")
    return True

def setup_environment():
    """Setup environment configuration."""
    print("\n🔧 Setting up environment...")
    
    env_file = Path('.env')
    env_example = Path('.env.example')
    
    if env_file.exists():
        print("  ℹ️  .env file already exists")
        overwrite = input("  Do you want to overwrite it? (y/N): ").lower()
        if overwrite != 'y':
            return True
    
    if not env_example.exists():
        print("  ❌ .env.example not found")
        return False
    
    # Copy example to .env
    with open(env_example, 'r') as f:
        env_content = f.read()
    
    with open(env_file, 'w') as f:
        f.write(env_content)
    
    print("  ✅ Created .env file from template")
    
    # Prompt for required values
    print("  📝 Please configure the following values:")
    
    aws_access_key = input("  AWS Access Key ID: ").strip()
    aws_secret_key = input("  AWS Secret Access Key: ").strip()
    aws_region = input("  AWS Region (default: us-east-1): ").strip() or "us-east-1"
    openai_key = input("  OpenAI API Key (optional): ").strip()
    
    # Update .env file
    env_content = env_content.replace('your_aws_access_key_here', aws_access_key)
    env_content = env_content.replace('your_aws_secret_key_here', aws_secret_key)
    env_content = env_content.replace('us-east-1', aws_region)
    if openai_key:
        env_content = env_content.replace('your_openai_api_key_here', openai_key)
    
    with open(env_file, 'w') as f:
        f.write(env_content)
    
    print("  ✅ Environment configured")
    return True

def install_dependencies():
    """Install Python dependencies."""
    print("\n📦 Installing dependencies...")
    
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)
        print("  ✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Failed to install dependencies: {e}")
        return False

def build_docker_images():
    """Build Docker images."""
    print("\n🐳 Building Docker images...")
    
    try:
        subprocess.run(['docker-compose', 'build'], check=True)
        print("  ✅ Docker images built successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Failed to build Docker images: {e}")
        return False

def test_services():
    """Test that services can start."""
    print("\n🧪 Testing services...")
    
    try:
        # Start services in detached mode
        subprocess.run(['docker-compose', 'up', '-d'], check=True)
        
        # Wait a bit for services to start
        import time
        time.sleep(30)
        
        # Check service status
        result = subprocess.run(['docker-compose', 'ps'], capture_output=True, text=True)
        print("  📊 Service status:")
        print(result.stdout)
        
        # Stop services
        subprocess.run(['docker-compose', 'down'], check=True)
        
        print("  ✅ Services test completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Service test failed: {e}")
        return False

def create_sample_data():
    """Create sample data for testing."""
    print("\n📊 Creating sample data...")
    
    sample_data_dir = Path('sample_data')
    sample_data_dir.mkdir(exist_ok=True)
    
    # Sample events for ML training
    sample_events = [
        {
            "timestamp": "2024-01-01T10:00:00Z",
            "source_ip": "192.168.1.100",
            "destination_port": 22,
            "protocol": "tcp",
            "event_type": "login_attempt",
            "honeypot_id": "honeypot-001",
            "session_id": "session-001",
            "additional_data": {"username": "admin", "password": "123456"}
        },
        {
            "timestamp": "2024-01-01T10:05:00Z",
            "source_ip": "10.0.0.50",
            "destination_port": 80,
            "protocol": "tcp",
            "event_type": "web_request",
            "honeypot_id": "honeypot-002",
            "session_id": "session-002",
            "additional_data": {"url": "/admin", "user_agent": "curl/7.68.0"}
        }
    ]
    
    with open(sample_data_dir / 'events.json', 'w') as f:
        json.dump(sample_events, f, indent=2)
    
    print("  ✅ Sample data created")
    return True

def print_next_steps():
    """Print next steps for the user."""
    print("\n🎉 CerberusMesh setup completed!")
    print("\n📋 Next steps:")
    print("  1. Review and update your .env file with actual API keys")
    print("  2. Deploy infrastructure: make deploy")
    print("  3. Start services: make dev")
    print("  4. Launch honeypots: make launch-honeypots")
    print("  5. Monitor activity: make monitor-attacks")
    
    print("\n🔗 Useful commands:")
    print("  make help           - Show all available commands")
    print("  make status         - Check service status")
    print("  make logs           - View application logs")
    print("  make monitor-attacks - Monitor attacks in real-time")
    
    print("\n🌐 Web interfaces:")
    print("  Dashboard API:  http://localhost:8000")
    print("  Grafana:        http://localhost:3000 (admin/cerberusmesh)")
    print("  Prometheus:     http://localhost:9090")
    
    print("\n📚 Documentation:")
    print("  See README.md for detailed usage instructions")
    print("  Check the docs/ directory for additional documentation")

def main():
    """Main setup function."""
    print_banner()
    
    print("Welcome to CerberusMesh setup!")
    print("This script will help you get started with the honeypot platform.\n")
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Setup environment
    if not setup_environment():
        print("❌ Environment setup failed")
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Dependency installation failed")
        sys.exit(1)
    
    # Build Docker images
    if not build_docker_images():
        print("❌ Docker build failed")
        sys.exit(1)
    
    # Test services
    if not test_services():
        print("❌ Service test failed")
        sys.exit(1)
    
    # Create sample data
    if not create_sample_data():
        print("❌ Sample data creation failed")
        sys.exit(1)
    
    # Print next steps
    print_next_steps()

if __name__ == "__main__":
    main()
