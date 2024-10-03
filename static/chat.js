const socket = io.connect('http://localhost:5000');

document.getElementById('send').onclick = function () {
    const receiver = document.getElementById('receiver').value;
    const message = document.getElementById('message').value;

    socket.emit('send_message', { receiver, message });
};

socket.on('receive_message', function (data) {
    document.getElementById('chat-log').innerHTML += '<div><strong>' + data.sender + ':</strong> ' + data.message + '</div>';
});

socket.emit('join');
