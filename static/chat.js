const socket = io.connect('http://localhost:5000');

// Handle sending messages
document.getElementById('send-button').onclick = function () {
    const messageInput = document.getElementById('message-input');
    const message = messageInput.value;

    // Get receiver's username
    const receiver = prompt("Enter receiver's username:");

    if (receiver && message) {
        // Emit the message and receiver to the server
        socket.emit('message', { message: message, receiver: receiver });
        messageInput.value = '';
    } else {
        alert("Both message and receiver are required!");
    }
};

// Handle incoming messages from the server
socket.on('message', function (data) {
    const messagesDiv = document.getElementById('messages');
    
    // Display the decrypted message with the sender's username
    messagesDiv.innerHTML += `<div><strong>${data.sender}:</strong> ${data.message}</div>`;
});

// Request previous messages from the server on page load
window.onload = function () {
    socket.emit('request_messages');
};

// Automatically scroll the chat window to the latest message
function scrollToBottom() {
    const messagesDiv = document.getElementById('messages');
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// Listen for incoming messages and scroll to the bottom after appending
socket.on('message', function () {
    scrollToBottom();
});
