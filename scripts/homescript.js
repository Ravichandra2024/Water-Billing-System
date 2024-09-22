function getRandomSample(array, n) {
    const shuffledArray = array.slice();
    for (let i = shuffledArray.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffledArray[i], shuffledArray[j]] = [shuffledArray[j], shuffledArray[i]];
    }
    return shuffledArray.slice(0, n);
}

fetch('https://api.worldnewsapi.com/search-news?api-key=4820b77803c54fc6b9938a3a30366b18&text=food%20wastage')
    .then(res => res.json())
    .then(data => {
        const x = getRandomSample(data.news, 1000);
        console.log(x);
        for (let i = 0; i < 10; i++) {
            const box = document.querySelectorAll('.box1')[i];
            const image = box.children[0];
            const title = box.children[1];
            const link = box.children[2];

            if (x[i].image === '' || x[i].image === null) {
                image.src = '';
            } else {
                image.src = x[i].image;
            }

            title.innerHTML = x[i].title;
            link.href = x[i].url;
        }
    })
    .catch(error => {
        console.error('An error occurred:', error);
    });
