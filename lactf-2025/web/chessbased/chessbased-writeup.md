# LA CTF 2025: web/chessbased

## Context
Chessbased is a search engine of a database of chess strategies based on if the search criteria is in the name or moves of a certain strategy. The code loops through the data in order and returns the first match. 

In app.js, we see that flag is added to the data at the end with the flag name, but the programmer also added a 'premium' field to all of the data with only the flag's premium boolean set to true. Then, when the code loops through the data to serach for the search criteria, the flag is skipped unless the user has the adminpw in the cookie. 

Since we are given an admin bot and through the code, we know that the admin bot can access the flag because it has the cookie. 

## Vulnerability
In app.js, the home page, `/render` and `/search` are the main pages we can access. We realize that `/render` can be accessed, allowing us to possibly put any argument (id) we'd like.

It seems the author [got too lost in the sauce](https://hackmd.io/@r2dev2/S1P0RYHYke#ChessbasedGigachessbased) and forgot to add authentification on render... 

## Exploitation
Since there is no authentification on `/render`, we can add `/render?id=flag` to the url and have it print the flag out.

## Remediation
To remediate this vulnerability, add authentification on the `/render` page to check that this user has the adminpw cookie. 

An example of this is the authentification author r2uwu2 adds on `/render` for the gigachessbased challenge.

```
app.get('/render', (req, res) => {
  const hasPremium = req.cookies.adminpw === adminpw;
  const id = req.query.id;
  const op = lookup.get(id);

  if (op.premium && !hasPremium) {
    return res.send('nice try buddy pay up');
  }

  res.send(`
    <p>${op?.name}</p>
    <p>${op?.moves}</p>
  `);
});
```