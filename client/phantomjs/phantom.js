var webpage = require('webpage');

var page = webpage.create();

page.open('https://google.com', function(status) {
	console.log(status);
	page.render('capture.jpeg', {format:'jpeg', quality:'100'});
	phantom.exit();
});

