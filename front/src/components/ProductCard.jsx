export default function ProductCard({ prod }) {
    return (
        <article className="bg-pink-200 p-2 m-2 flex-col justify-center items-center">
            <p>{prod.title}</p>
            <p>${prod.price}</p>
            <p>{prod.stock}</p>
            <p>{prod.category}</p>
        </article>
    )
}