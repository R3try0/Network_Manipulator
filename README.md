# Network Manipulator

**Network Manipulator** is a powerful tool designed for network analysis and manipulation. By leveraging ARP (Address Resolution Protocol), it scans the local network to identify connected devices, providing users with valuable insights into their network environment. Additionally, it offers functionality for MAC address spoofing, allowing users to change their device's MAC address for privacy or testing purposes.

![Network Manipulator](https://github.com/user-attachments/assets/914168b0-820c-445e-80c5-cd35d081c553)

## Features
- **GUI**: Fully functional User Interface.
- **Network Scanning**: Discover all devices connected to your local network.
- **MAC Address Spoofing**: Change your device's MAC address easily.

## Testing Status
- **Windows Testing**: ✅ Passed
- **Linux Testing**: ⏳ Pending

## Standalone Executable
- **Windows**: Compiled using Nuitka for optimal performance.
- **Linux**: Can be run directly without additional compilation for now.

## Usage

### Windows
1. **Download the Executable**: 
   - Go to the **[Releases](https://github.com/R3try0/Network_Manipulator/)** section of the repository.
   - Download the latest standalone executable for Windows.

2. **Run the Application**: 
   - Locate the downloaded file in your Downloads folder or the specified directory.
   - Double-click the executable to launch **Network Manipulator**. The user-friendly interface will open, allowing you to start using the tool immediately.

### Linux
1. **Install Dependencies**: 
   - Open your terminal.
   - Navigate to the directory where you cloned or downloaded the repository.
   - Run the following command to install the required Python packages:
     ```bash
     pip install -r requirements.txt
     ```

2. **Launch the Application**: 
   - After the dependencies are installed, execute the following command to start the application:
     ```bash
     python src.py
     ```
   - The graphical user interface will appear, ready for you to explore its features.

### Additional Notes
- Ensure you have Python and pip installed on your Linux system before proceeding with the installation.
- For optimal performance, consider running the application with administrative privileges, especially when performing network scans or MAC address spoofing.

## Contributing
Contributions are welcome! Please feel free to submit issues or pull requests.

## License
This project is licensed under the MIT License. You are free to copy, modify, and distribute the code, but please provide appropriate credit to the original author. For more details, see the LICENSE file.
