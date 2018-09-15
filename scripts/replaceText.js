function ReplaceText() {
    var r = Math.floor(Math.random() * 6);
    var quotes = ["...o.no.he.didnt...",
                  "...take.that.playa...",
                  "...ah.yeah...",
                  "...fill.em.up...",
                  "...fo.shizzle...",
                  "...say.what?..."];
    document.getElementById('random').innerHTML =
        document.getElementById('random').innerHTML.replace('...', quotes[r]);
}
window.onload = ReplaceText;

