fetch('/bills')
.then(res=>res.json())
.then(data=>{
    if(data.success){
        generateTableRows(data.bills)
    }
    else{
        alert('Failed to fetch bills');
    }
});
function generateTableRows(billDetails) {
    const tableBody = document.getElementById('billTableBody');
    
    billDetails.forEach(detail => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${detail.date}</td>
            <td>${detail.amount}</td>
            <td>${detail.status}</td>
        `;
        tableBody.appendChild(row);
    });
}
generateTableRows();