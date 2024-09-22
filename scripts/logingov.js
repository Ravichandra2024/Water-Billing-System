document.querySelector('#logingovcheck1').addEventListener('click', (event) => {
    event.preventDefault(); 
    var u = document.querySelector('#user1').value;
    var p = document.querySelector('#password1').value;
    if (u === '') {
        alert('Enter the user name');
    } else if (p === '') {
        alert('Enter the password');
    } else {
        verify1(u, p);
    }
});

function verify1(u, p) {
    var url = '/govlogin/' + u + '/' + p;
    console.log(url)
    console.log('login');
    fetch(url)
    .then(res=>res.json())
    .then(data=>{
        console.log(data)
       if(data.success){
          alert('login successful');
          parent.window.location.href = '/govdashboard';
       }
       else{
          alert(data.message);
       }
    })
}