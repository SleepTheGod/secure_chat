const socket = io.connect('http://localhost:5000');

document.getElementById('send-button').onclick = function () {
    const messageInput = document.getElementById('message-input');
    const message = messageInput.value;

    // Get receiver username (could be improved for a group chat)
    const receiver = prompt("Enter receiver's username:");

    socket.emit('message', { message: message, receiver: receiver });

    messageInput.value = '';
};

socket.on('message', function (data) {
    const messagesDiv = document.getElementById('messages');
    messagesDiv.innerHTML += '<div>' + data.content + '</div>';
});

// Request messages from the server on load
socket.emit('request_messages');
